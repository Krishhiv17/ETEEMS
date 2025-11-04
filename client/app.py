# client/app.py
import asyncio, os, sys, json, base64, random, time, getpass, pathlib, re
from collections import deque
from typing import Optional, Tuple, Dict, Callable, Awaitable
from client.config import WS_BASE  # e.g., "ws://127.0.0.1:5088"
from client.transport import Transport
from client.storage import Storage
from client.framing import (
    build_frame, parse_and_verify_frame,
    BadTag, ReplayError, OutOfOrderError, ShortFrame,
)
from client.crypto import hkdf_derive, dh_gen, dh_shared  # uses your Phase-2 helpers
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------- simple helpers ----------

DATA_DIR = os.path.expanduser("~/.e2e")

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

def _sanitize_username(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", name.strip())
    return cleaned or "user"

def _user_data_dir(username: str) -> str:
    return os.path.join(DATA_DIR, _sanitize_username(username))

def int_to_bytes(n: int) -> bytes:
    if n == 0: return b"\x00"
    l = (n.bit_length() + 7) // 8
    return n.to_bytes(l, "big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def ensure_dir(path: str):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    
def compute_pubkey_fingerprint(pub_pem: bytes) -> bytes:
    """SHA-256 over DER SubjectPublicKeyInfo of the RSA public key."""
    pub = load_pem_public_key(pub_pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h = hashes.Hash(hashes.SHA256())
    h.update(der)
    return h.finalize()  # 32 bytes


def load_or_create_identity(priv_path: str, pub_path: str) -> Tuple[bytes, bytes]:
    """
    Return (priv_pem_bytes, pub_pem_bytes).
    If missing, generate a fresh 2048-bit RSA keypair and store under ~/.e2e/keys/.
    """
    ensure_dir(os.path.dirname(priv_path))
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f: priv_pem = f.read()
        with open(pub_path,  "rb") as f: pub_pem  = f.read()
        return priv_pem, pub_pem

    # generate
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)
    print(f"[keys] generated RSA keypair at {os.path.dirname(priv_path)}")
    return priv_pem, pub_pem

# ---------- DB helpers (use Storage.conn directly to avoid API mismatch) ----------

def db_upsert_contact(
    s: Storage,
    alias: str,
    pub_pem: Optional[bytes],
    remote_username: Optional[str] = None,
    verified: bool = False,
) -> None:
    if pub_pem is None:
        raise ValueError("pub_pem is required; contacts.fingerprint is NOT NULL")

    # Compute SHA-256 fingerprint of the SubjectPublicKeyInfo (DER)
    fp_hex = compute_pubkey_fingerprint(pub_pem).hex()
    s.contact_add(alias, pub_pem, fp_hex, verified=verified, remote_username=remote_username)



def db_get_contact_pub(s: Storage, name: str) -> Optional[bytes]:
    row = s.contact_get(name)
    if not row:
        return None
    return row["rsa_pub_pem"] if row["rsa_pub_pem"] else None

def db_get_contact_row(s: Storage, name: str) -> Optional[dict]:
    row = s.contact_get(name)
    return dict(row) if row else None

def db_get_contact_by_remote(s: Storage, remote_username: str) -> Optional[dict]:
    row = s.contact_get_by_remote(remote_username)
    return dict(row) if row else None

def db_get_session(s: Storage, contact: str) -> Optional[dict]:
    sess = s.session_get(contact)
    if not sess:
        return None

    bundle_ab = sess.get("bundle_ab")
    bundle_ba = sess.get("bundle_ba")
    if bundle_ab is None or bundle_ba is None:
        return None

    return {
        "contact": contact,
        "session_id": int(sess["session_id"]),
        "seq_send": int(sess["seq_send"]),
        "seq_recv_next": int(sess["seq_recv_next"]),
        "k_enc_ab": bundle_ab["K_enc"],
        "k_mac_ab": bundle_ab["K_mac"],
        "ivseed_ab": bundle_ab["IVseed"],
        "k_enc_ba": bundle_ba["K_enc"],
        "k_mac_ba": bundle_ba["K_mac"],
        "ivseed_ba": bundle_ba["IVseed"],
    }

def db_put_session(s: Storage, contact: str, session_id: int,
                   Kenc_ab: bytes, Kmac_ab: bytes, IVseed_ab: bytes,
                   Kenc_ba: bytes, Kmac_ba: bytes, IVseed_ba: bytes,
                   seq_send: int, seq_recv_next: int) -> None:
    s.session_upsert(
        contact=contact,
        session_id=session_id,
        bundle_ab={"K_enc": Kenc_ab, "K_mac": Kmac_ab, "IVseed": IVseed_ab},
        bundle_ba={"K_enc": Kenc_ba, "K_mac": Kmac_ba, "IVseed": IVseed_ba},
        seq_send=seq_send,
        seq_recv_next=seq_recv_next,
        last_rekey_at=int(time.time()),
    )

def db_bump_seq_send(s: Storage, contact: str, new_seq: int) -> None:
    s.conn.execute("UPDATE sessions SET seq_send=? WHERE contact=?", (new_seq, contact))
    s.conn.commit()

def db_set_seq_recv_next(s: Storage, contact: str, new_seq_next: int) -> None:
    s.conn.execute("UPDATE sessions SET seq_recv_next=? WHERE contact=?", (new_seq_next, contact))
    s.conn.commit()

def db_store_message(s: Storage, contact: str, direction: str, session_id: int, seq: int, plaintext: bytes) -> None:
    s.message_add(
        contact=contact,
        direction=direction,
        plaintext=plaintext,
        remote_id=seq,
        session_epoch=session_id,
        encrypt_body=True,
    )

# ---------- Session bootstrap payloads ----------

# We’ll send SESSION payloads as JSON (bytes) with these shapes:
#  INIT: {"t":"init","sid":<int>,"dh_b64":"...","me":"<name>"}
#  RESP: {"t":"resp","sid":<int>,"dh_b64":"...","me":"<name>"}

def build_init_payload(sid: int, dh_pub: int, me: str) -> bytes:
    obj = {"t":"init","sid":int(sid),"dh_b64": b64e(int_to_bytes(dh_pub)),"me": me}
    return json.dumps(obj,separators=(',',':')).encode("utf-8")

def build_resp_payload(sid: int, dh_pub: int, me: str) -> bytes:
    obj = {"t":"resp","sid":int(sid),"dh_b64": b64e(int_to_bytes(dh_pub)),"me": me}
    return json.dumps(obj,separators=(',',':')).encode("utf-8")

def parse_session_payload(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))

def derive_keys(shared_secret_bytes: bytes, a_name: str, b_name: str) -> Tuple[dict, dict]:
    """
    HKDF derive per-direction keys.
    Returns (A->B, B->A) dicts with keys: K_enc, K_mac, IVseed.
    """
    info = ("e2e-messenger v1|%s<->%s" % (a_name, b_name)).encode("utf-8")
    okm_len = (16+32+16) * 2  # Kenc(16) + Kmac(32) + IVseed(16) times two directions
    okm = hkdf_derive(shared_secret_bytes, info=info, length=okm_len)
    off = 0
    def take(n): 
        nonlocal off
        r = okm[off:off+n]; off += n; return r
    AtoB = {"K_enc": take(16), "K_mac": take(32), "IVseed": take(16)}
    BtoA = {"K_enc": take(16), "K_mac": take(32), "IVseed": take(16)}
    return AtoB, BtoA

# ---------- Client runtime ----------

class ClientRuntime:
    def __init__(self, username: str, passphrase: str):
        self.username = username
        self.passphrase = passphrase
        self.data_dir = _user_data_dir(username)
        ensure_dir(self.data_dir)
        self.keys_dir = os.path.join(self.data_dir, "keys")
        self._priv_pem_path = os.path.join(self.keys_dir, "identity_private.pem")
        self._pub_pem_path = os.path.join(self.keys_dir, "identity_public.pem")
        self._db_path = os.path.join(self.data_dir, "client.db")
        self.storage = Storage(db_path=self._db_path)
        self.transport: Optional[Transport] = None
        self.priv_pem: Optional[bytes] = None
        self.pub_pem: Optional[bytes]  = None
        self._pending_pubkeys: dict[str, asyncio.Future] = {}
        self._prompt_clear: Optional[Callable[[], Awaitable[None]]] = None
        self._prompt_render: Optional[Callable[[], Awaitable[None]]] = None
        self._prompt_visible: bool = False
        self._pending_prompts: deque[dict] = deque()
        self._active_prompt: Optional[dict] = None
        self._pending_friend_outgoing: Dict[str, str] = {}
        self._pending_chat_outgoing: Dict[str, str] = {}
        self.active_contact: Optional[str] = None
        self._dh_pending: Dict[str, tuple[int, int, str]] = {}

    async def start(self):
        # DB & vault
        self.storage.init_schema()
        try:
            self.storage.login(self.passphrase)
        except ValueError as e:
            self.storage.logout()
            raise SystemExit(
                "[vault] Invalid passphrase for existing vault. Use the original passphrase "
                f"or remove {self._db_path} to reset."
            ) from e
        except RuntimeError:
            # first time setup
            self.storage.first_time_setup(self.passphrase)
            self.storage.logout()
            self.storage = Storage(db_path=self._db_path)
            self.storage.init_schema()
            self.storage.login(self.passphrase)
        except Exception:
            self.storage.logout()
            raise

        # identity keys (PEM files under ~/.e2e/keys)
        self.priv_pem, self.pub_pem = load_or_create_identity(self._priv_pem_path, self._pub_pem_path)

        # upsert our own contact record (optional, for convenience)
        db_upsert_contact(self.storage, self.username, self.pub_pem, remote_username=self.username, verified=True)

        # connect transport
        self.transport = Transport(WS_BASE, self.username, self.priv_pem, privkey_pass=None)
        await self.transport.connect()
        # spawn receive loop
        asyncio.create_task(self.transport.run_receive_loop(self._on_frame, self._on_session, self._on_pubkey))
        print(f"[client] connected as {self.username}")

    # ----- session bootstrap (initiator) -----

    async def start_session_with(self, alias: str, remote_username: str, force: bool = False):
        sess = db_get_session(self.storage, alias)
        if sess and not force:
            print(f"[session] already active with {alias} (sid={sess['session_id']})")
            return

        a, A = dh_gen()
        sid = random.randint(1, 0xFFFF)
        self._dh_pending[remote_username] = (a, A, alias)

        payload = build_init_payload(sid, A, self.username)
        await self.transport.send_session(remote_username, payload)
        print(f"[session:init] sent to {alias}: sid={sid}, A=({A.bit_length()} bits)")

    # ----- send message -----

    async def send_text(self, alias: str, text: str):
        row = self.storage.contact_get(alias)
        if not row:
            print(f"[send] unknown contact '{alias}'.")
            return
        remote_username = row["remote_username"] or alias
        sess = db_get_session(self.storage, alias)
        if not sess:
            await self.start_session_with(alias, remote_username)
            for _ in range(50):
                await asyncio.sleep(0.1)
                sess = db_get_session(self.storage, alias)
                if sess:
                    break
            if not sess:
                print(f"[send] waiting for secure session with {alias}; try again shortly")
                return
        seq = int(sess["seq_send"])
        keys = {"K_enc": sess["k_enc_ab"], "K_mac": sess["k_mac_ab"], "IVseed": sess["ivseed_ab"]}
        sid = int(sess["session_id"])
        pt = text.encode("utf-8")
        frame = build_frame(keys, session_id=sid, seq=seq, plaintext=pt)
        await self.transport.send_frame(remote_username, sid, frame)
        db_store_message(self.storage, alias, "out", sid, seq, pt)
        db_bump_seq_send(self.storage, alias, seq + 1)
        print(f"You: {text}")

    # ----- receive hooks from Transport -----

    async def _on_session(self, from_user: str, payload: bytes):
        try:
            obj = parse_session_payload(payload)
        except Exception:
            print(f"[session] bad payload from {from_user}")
            return

        t = obj.get("t")
        if t == "friend_req":
            await self._handle_friend_request(from_user, obj)
            return
        if t == "friend_resp":
            await self._handle_friend_response(from_user, obj)
            return
        if t == "chat_req":
            await self._handle_chat_request(from_user, obj)
            return
        if t == "chat_resp":
            await self._handle_chat_response(from_user, obj)
            return

        sid = int(obj.get("sid", 0))
        dh_b = b64d(obj.get("dh_b64", ""))
        peer_pub = bytes_to_int(dh_b)

        if t == "init":
            alias = self._alias_for_remote(from_user)
            if alias is None:
                alias = from_user
                try:
                    pem = await self.fetch_remote_pubkey(from_user)
                except Exception as exc:
                    print(f"[session] failed to fetch key for {from_user}: {exc}")
                    return
                db_upsert_contact(self.storage, alias, pem, remote_username=from_user, verified=False)

            b, B = dh_gen()
            s_int = dh_shared(b, peer_pub)
            s_bytes = int_to_bytes(s_int)
            AtoB, BtoA = derive_keys(s_bytes, from_user, self.username)
            db_put_session(
                self.storage,
                alias,
                sid,
                Kenc_ab=BtoA["K_enc"], Kmac_ab=BtoA["K_mac"], IVseed_ab=BtoA["IVseed"],
                Kenc_ba=AtoB["K_enc"], Kmac_ba=AtoB["K_mac"], IVseed_ba=AtoB["IVseed"],
                seq_send=0,
                seq_recv_next=0,
            )
            resp = build_resp_payload(sid, B, self.username)
            await self.transport.send_session(from_user, resp)
            if not self.active_contact:
                self.active_contact = alias
            print(f"[session:resp] to={alias} sid={sid}, derived keys; sent B ({B.bit_length()} bits)")
            return

        if t == "resp":
            pending = self._dh_pending.pop(from_user, None)
            if not pending:
                print("[session] got RESP but no pending INIT; ignoring")
                return
            a, _A, alias = pending
            s_int = dh_shared(a, peer_pub)
            s_bytes = int_to_bytes(s_int)
            AtoB, BtoA = derive_keys(s_bytes, self.username, from_user)
            db_put_session(
                self.storage,
                alias,
                sid,
                Kenc_ab=AtoB["K_enc"], Kmac_ab=AtoB["K_mac"], IVseed_ab=AtoB["IVseed"],
                Kenc_ba=BtoA["K_enc"], Kmac_ba=BtoA["K_mac"], IVseed_ba=BtoA["IVseed"],
                seq_send=0,
                seq_recv_next=0,
            )
            self.active_contact = alias
            print(f"[session:init→ready] with {alias} sid={sid}, keys installed")
            return

        print(f"[session] unknown type from {from_user}: {t}")

    async def _on_frame(self, from_user: str, session_id: int, frame: bytes):
        restore_prompt = False
        if self._prompt_visible and self._prompt_clear:
            try:
                await self._prompt_clear()
                restore_prompt = True
                self._prompt_visible = False
            except Exception:
                restore_prompt = False

        alias = self._alias_for_remote(from_user) or from_user
        sess = db_get_session(self.storage, alias)
        if not sess or int(sess["session_id"]) != int(session_id):
            print(f"[recv] unknown session from={from_user} sid={session_id}")
            return
        expected = int(sess["seq_recv_next"])
        keys = {"K_enc": sess["k_enc_ba"], "K_mac": sess["k_mac_ba"], "IVseed": sess["ivseed_ba"]}

        try:
            (_v,_f,_sid, seq), pt = parse_and_verify_frame(keys, frame, expected_session_id=session_id, expected_seq=expected)
        except ReplayError:
            print(f"[recv] replay from {from_user} (ignored)")
            return
        except OutOfOrderError:
            print(f"[recv] out-of-order from {from_user} (ignored)")
            return
        except BadTag:
            print(f"[recv] BAD TAG from {from_user} (tampered?)")
            return
        except ShortFrame:
            print(f"[recv] short/bad frame from {from_user}")
            return

        # accept
        db_store_message(self.storage, alias, "in", session_id, seq, pt)
        db_set_seq_recv_next(self.storage, alias, seq + 1)
        try:
            print(f"{from_user}: {pt.decode('utf-8', errors='replace')}")
        except Exception:
            print(f"{from_user}: <{len(pt)} bytes>")
        if restore_prompt and self._prompt_render:
            try:
                await self._prompt_render()
                self._prompt_visible = True
            except Exception:
                pass

    async def fetch_remote_pubkey(self, contact: str) -> bytes:
        if not self.transport:
            raise RuntimeError("transport not connected")
        key = contact.strip()
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = self._pending_pubkeys.get(key)
        if fut and not fut.done():
            fut.cancel()
        fut = loop.create_future()
        self._pending_pubkeys[key] = fut
        try:
            await self.transport.request_pubkey(key)
            pem = await asyncio.wait_for(fut, timeout=10.0)
            return pem
        finally:
            self._pending_pubkeys.pop(key, None)

    async def _on_pubkey(self, msg: dict):
        name = msg.get("user")
        fut = self._pending_pubkeys.get(name)
        if not fut or fut.done():
            return
        if msg.get("type") == "PUBKEY_RESPONSE":
            pem_text = msg.get("rsa_pub_pem", "")
            fut.set_result(pem_text.encode("utf-8"))
        else:
            reason = msg.get("reason", "unknown")
            fut.set_exception(ValueError(reason))

    def register_prompt_hooks(
        self,
        clear_cb: Optional[Callable[[], Awaitable[None]]],
        render_cb: Optional[Callable[[], Awaitable[None]]],
    ) -> None:
        self._prompt_clear = clear_cb
        self._prompt_render = render_cb
        self._prompt_visible = False

    def _remote_for_alias(self, alias: str) -> Optional[str]:
        row = self.storage.contact_get(alias)
        if row:
            remote = row["remote_username"]
            return remote or alias
        return None

    def _alias_for_remote(self, remote_username: str) -> Optional[str]:
        row = self.storage.contact_get_by_remote(remote_username)
        if row:
            return row["name"]
        return None

    async def _ensure_contact_alias(
        self,
        alias: str,
        remote_username: str,
        verified: bool,
        pem: Optional[bytes] = None,
    ) -> None:
        row = self.storage.contact_get(alias)
        if row:
            if verified and not row["verified"]:
                self.storage.contact_verify(alias, True)
            return
        if pem is None:
            pem = await self.fetch_remote_pubkey(remote_username)
        db_upsert_contact(
            self.storage,
            alias,
            pem,
            remote_username=remote_username,
            verified=verified,
        )

    async def _send_control(self, remote_username: str, obj: dict) -> None:
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        await self.transport.send_session(remote_username, payload)

    async def _handle_friend_request(self, from_user: str, obj: dict) -> None:
        existing_row = self.storage.contact_get_by_remote(from_user)
        existing = dict(existing_row) if existing_row else None
        if existing and existing["verified"]:
            await self._send_control(
                from_user,
                {
                    "t": "friend_resp",
                    "status": "accept",
                    "alias": existing["name"],
                    "pem": self.pub_pem.decode("utf-8"),
                },
            )
            return
        pem_b64 = obj.get("pem_b64")
        if pem_b64:
            pem = base64.b64decode(pem_b64.encode("ascii"))
        else:
            try:
                pem = await self.fetch_remote_pubkey(from_user)
            except Exception as exc:
                print(f"[friend] failed to fetch key for {from_user}: {exc}")
                await self._send_control(from_user, {"t": "friend_resp", "status": "error"})
                return
        prompt = {
            "type": "friend_confirm",
            "remote": from_user,
            "pem": pem,
        }
        self._pending_prompts.append(prompt)
        await self._maybe_show_prompt()

    async def _handle_friend_response(self, from_user: str, obj: dict) -> None:
        status = obj.get("status")
        alias = self._pending_friend_outgoing.pop(from_user, obj.get("alias") or from_user)
        if status != "accept":
            print(f"[friend] {from_user} rejected your request.")
            return
        pem_field = obj.get("pem_b64")
        if pem_field:
            pem = base64.b64decode(pem_field.encode("ascii"))
        else:
            print(f"[friend] peer response missing key material; fetching from relay...")
            try:
                pem = await self.fetch_remote_pubkey(from_user)
            except Exception as exc:
                print(f"[friend] could not fetch key for {from_user}: {exc}")
                return
        await self._ensure_contact_alias(alias, from_user, True, pem=pem)
        self.storage.contact_verify(alias, True)
        print(f"[friend] {from_user} accepted. Saved as {alias}.")

    async def _handle_chat_request(self, from_user: str, obj: dict) -> None:
        row_obj = self.storage.contact_get_by_remote(from_user)
        row = dict(row_obj) if row_obj else None
        if not row or not row.get("verified"):
            await self._send_control(from_user, {"t": "chat_resp", "status": "reject"})
            print(f"[chat] Ignored chat request from {from_user}; not in friends list.")
            return
        alias = row["name"]
        prompt = {
            "type": "chat_confirm",
            "remote": from_user,
            "alias": alias,
        }
        self._pending_prompts.append(prompt)
        await self._maybe_show_prompt()

    async def _handle_chat_response(self, from_user: str, obj: dict) -> None:
        alias = self._pending_chat_outgoing.pop(from_user, None)
        status = obj.get("status")
        if status != "accept":
            print(f"[chat] {from_user} declined your chat request.")
            return
        if alias is None:
            alias = self._alias_for_remote(from_user) or from_user
        print(f"[chat] {from_user} accepted. Establishing secure session...")
        await self.start_session_with(alias, from_user, force=True)
        self.active_contact = alias


    async def _accept_friend(self, remote_username: str, alias: str, pem: bytes) -> None:
        await self._ensure_contact_alias(alias, remote_username, True, pem=pem)
        self.storage.contact_verify(alias, True)
        print(f"[friend] Added {alias}.")

    async def _maybe_show_prompt(self) -> None:
        if self._active_prompt or not self._pending_prompts:
            return
        prompt = self._pending_prompts.popleft()
        self._active_prompt = prompt
        p_type = prompt["type"]
        if p_type == "friend_confirm":
            print(f"[friend] {prompt['remote']} wants to connect. Accept? (Y/n): ", end="", flush=True)
        elif p_type == "friend_alias":
            default_alias = prompt.get("default_alias", prompt["remote"])
            prompt["default_alias"] = default_alias
            print(f"[friend] Enter a name to display for {prompt['remote']} (default: {default_alias}): ", end="", flush=True)
        elif p_type == "chat_confirm":
            print(f"[chat] {prompt['alias']} wants to start a chat. Accept? (Y/n): ", end="", flush=True)

    async def handle_prompt_input(self, line: str) -> bool:
        if not self._active_prompt:
            return False
        prompt = self._active_prompt
        self._active_prompt = None
        p_type = prompt["type"]
        response = line.strip().lower()
        if p_type == "friend_confirm":
            accepted = response in ("", "y", "yes")
            if accepted:
                alias_prompt = {
                    "type": "friend_alias",
                    "remote": prompt["remote"],
                    "pem": prompt["pem"],
                    "default_alias": prompt["remote"],
                }
                self._active_prompt = alias_prompt
                print(f"[friend] Enter a name to display for {prompt['remote']} (default: {prompt['remote']}): ", end="", flush=True)
            else:
                await self._send_control(prompt["remote"], {"t": "friend_resp", "status": "reject"})
                print(f"[friend] Rejected request from {prompt['remote']}.")
                await self._maybe_show_prompt()
            return True
        if p_type == "friend_alias":
            alias = line.strip() or prompt.get("default_alias", prompt["remote"])
            await self._accept_friend(prompt["remote"], alias, prompt["pem"])
            await self._send_control(
                prompt["remote"],
                {
                    "t": "friend_resp",
                    "status": "accept",
                    "alias": alias,
                    "pem_b64": base64.b64encode(self.pub_pem).decode("ascii"),
                },
            )
            await self._maybe_show_prompt()
            return True
        if p_type == "chat_confirm":
            accepted = response in ("", "y", "yes")
            if accepted:
                self.active_contact = prompt["alias"]
                await self._handle_chat_response_local(prompt["remote"], True)
                print(f"[chat] Accepted chat with {prompt['alias']}.")
            else:
                await self._handle_chat_response_local(prompt["remote"], False)
                print(f"[chat] Declined chat with {prompt['alias']}.")
            await self._maybe_show_prompt()
            return True
        return False

    async def _handle_chat_response_local(self, from_user: str, accepted: bool) -> None:
        status = "accept" if accepted else "reject"
        await self._send_control(from_user, {"t": "chat_resp", "status": status})

    async def show_online(self) -> None:
        if not self.transport:
            print("[online] transport not ready yet.")
            return
        try:
            users = await self.transport.request_online()
        except Exception as exc:
            print(f"[online] error: {exc}")
            return
        if not users:
            print("[online] no other users connected.")
        else:
            print("[online] " + ", ".join(users))

    async def send_friend_request(self, alias: str, remote_username: str) -> None:
        alias = alias.strip()
        if not alias:
            print("[friend] alias required.")
            return
        remote_username = remote_username.strip()
        if not remote_username:
            print("[friend] remote username required.")
            return
        if remote_username == self.username:
            print("[friend] cannot add yourself.")
            return
        existing_alias_row = self.storage.contact_get(alias)
        if existing_alias_row:
            remote_bound = existing_alias_row["remote_username"]
            if remote_bound not in (None, remote_username):
                print(f"[friend] alias '{alias}' is already used for another contact.")
                return
        existing_alias = dict(existing_alias_row) if existing_alias_row else None
        if existing_alias and existing_alias.get("remote_username") not in (None, remote_username):
            print(f"[friend] alias '{alias}' is already used for another contact.")
            return
        existing_row = self.storage.contact_get_by_remote(remote_username)
        existing = dict(existing_row) if existing_row else None
        if existing and existing.get("verified"):
            print(f"[friend] already connected with {existing['name']}.")
            return
        if remote_username in self._pending_friend_outgoing:
            print(f"[friend] request to {remote_username} already pending.")
            return
        self._pending_friend_outgoing[remote_username] = alias
        await self._send_control(
            remote_username,
            {
                "t": "friend_req",
                "pem_b64": base64.b64encode(self.pub_pem).decode("ascii"),
            },
        )
        print(f"[friend] request sent to {remote_username}. Waiting for response...")

    async def send_chat_request(self, alias: str) -> None:
        alias = alias.strip()
        if not alias:
            print("[chat] usage: /chat <alias>")
            return
        row_obj = self.storage.contact_get(alias)
        row = dict(row_obj) if row_obj else None
        if not row or not row.get("verified"):
            print(f"[chat] '{alias}' is not an accepted friend yet.")
            return
        remote_username = row.get("remote_username") or alias
        sess = db_get_session(self.storage, alias)
        if sess:
            self.active_contact = alias
            print(f"[chat] Session already active with {alias}.")
            return
        self._pending_chat_outgoing[remote_username] = alias
        await self._send_control(remote_username, {"t": "chat_req"})
        print(f"[chat] request sent to {alias}. Awaiting approval...")

    async def rekey_active(self) -> None:
        if not self.active_contact:
            print("[chat] no active chat to rekey.")
            return
        remote_username = self._remote_for_alias(self.active_contact)
        if not remote_username:
            print("[chat] missing remote mapping for active contact.")
            return
        await self.start_session_with(self.active_contact, remote_username, force=True)
        print(f"[rekey] started new session with {self.active_contact}.")

    async def handle_plain_message(self, text: str) -> None:
        if not self.active_contact:
            print("[chat] no active chat. Use /chat <alias> to start one.")
            return
        await self.send_text(self.active_contact, text)

# ---------- CLI ----------

HELP = """
Commands:
  /online                        List currently connected users
  /add <alias> @<user>           Send a friend request to <user>
  /chat <alias>                  Request a secure chat with a friend
  /rekey                         Force a key rotation with the active chat
  /help                          Show this help
  /quit                          Exit the client
Type a message to send it to the active chat.
"""

async def cli_main():
    print("[boot] Phase 5 glue: transport ↔ crypto ↔ storage")
    username = input("Enter your username: ").strip()
    pw = getpass.getpass("Vault passphrase: ")

    client = ClientRuntime(username, pw)
    await client.start()

    loop = asyncio.get_running_loop()

    # simple stdin reader
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, os.fdopen(0, "rb", buffering=0))
    print(HELP)

    async def prompt_clear():
        if not sys.stdin.isatty():
            return
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        client._prompt_visible = False

    async def prompt_render():
        if not sys.stdin.isatty() or client._active_prompt:
            return
        label = f"{client.active_contact}> " if client.active_contact else "> "
        sys.stdout.write(label)
        sys.stdout.flush()
        client._prompt_visible = True

    async def clear_input_echo():
        if not sys.stdin.isatty():
            return
        sys.stdout.write("\033[F\r\033[K")
        sys.stdout.flush()

    client.register_prompt_hooks(prompt_clear, prompt_render)

    await prompt_render()

    while True:
        raw_line = await reader.readline()
        if not raw_line:
            break
        if client._prompt_visible:
            await prompt_clear()
        line = raw_line.decode("utf-8", errors="ignore").strip()
        if sys.stdin.isatty() and not line.startswith("/"):
            await clear_input_echo()
        elif sys.stdin.isatty() and line.startswith("/"):
            print()
        if client._active_prompt:
            await client.handle_prompt_input(line)
            await prompt_render()
            continue
        if not line:
            await prompt_render()
            continue
        if line == "/quit":
            break
        if line == "/help":
            print(HELP)
            await prompt_render()
            continue
        if line == "/online":
            await client.show_online()
            await prompt_render()
            continue
        if line.startswith("/add "):
            parts = line.split()
            if len(parts) != 3 or not parts[2].startswith("@"):
                print("usage: /add <alias> @<username>")
                await prompt_render()
                continue
            alias = parts[1]
            remote = parts[2].lstrip("@")
            await client.send_friend_request(alias, remote)
            await prompt_render()
            continue
        if line.startswith("/chat "):
            _, alias = line.split(maxsplit=1)
            await client.send_chat_request(alias.strip())
            await prompt_render()
            continue
        if line == "/rekey":
            await client.rekey_active()
            await prompt_render()
            continue
        if line.startswith("/"):
            print("Unknown command. Type /help")
            await prompt_render()
            continue

        await client.handle_plain_message(line)
        await prompt_render()

    # shutdown
    try:
        if client.transport:
            await client.transport.close()
    finally:
        client.storage.logout()
        print("[bye]")

if __name__ == "__main__":
    asyncio.run(cli_main())
