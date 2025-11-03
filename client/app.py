# client/app.py
import asyncio, os, sys, json, base64, random, time, getpass, pathlib, re
from typing import Optional, Tuple, Dict, Callable, Awaitable
import sys
from client.config import WS_BASE  # e.g., "ws://127.0.0.1:5088"
from client.transport import Transport
from client.storage import Storage
from client.framing import (
    build_frame, parse_and_verify_frame,
    BadTag, ReplayError, OutOfOrderError, ShortFrame,
)
from client.crypto import hkdf_derive, dh_gen, dh_shared  # uses your Phase-2 helpers

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
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

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
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
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

def db_upsert_contact(s: Storage, name: str, pub_pem: Optional[bytes]) -> None:
    if pub_pem is None:
        raise ValueError("pub_pem is required; contacts.fingerprint is NOT NULL")

    # Compute SHA-256 fingerprint of the SubjectPublicKeyInfo (DER)
    fp_hex = compute_pubkey_fingerprint(pub_pem).hex()
    s.contact_add(name, pub_pem, fp_hex, verified=False)



def db_get_contact_pub(s: Storage, name: str) -> Optional[bytes]:
    row = s.contact_get(name)
    if not row:
        return None
    return row["rsa_pub_pem"] if row["rsa_pub_pem"] else None

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
        # ephemeral DH for initiator
        self._dh_priv: Optional[int] = None
        self._dh_pub:  Optional[int] = None
        self._pending_pubkeys: dict[str, asyncio.Future] = {}
        self._prompt_clear: Optional[Callable[[], Awaitable[None]]] = None
        self._prompt_render: Optional[Callable[[], Awaitable[None]]] = None
        self._prompt_visible: bool = False

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
        db_upsert_contact(self.storage, self.username, self.pub_pem)

        # connect transport
        self.transport = Transport(WS_BASE, self.username, self.priv_pem, privkey_pass=None)
        await self.transport.connect()
        # spawn receive loop
        asyncio.create_task(self.transport.run_receive_loop(self._on_frame, self._on_session, self._on_pubkey))
        print(f"[client] connected as {self.username}")

    # ----- session bootstrap (initiator) -----

    async def start_session_with(self, peer: str, force: bool = False):
        sess = db_get_session(self.storage, peer)
        if sess and not force:
            # quietly reuse existing session
            return

        # generate ephemeral DH and session id
        a, A = dh_gen()
        sid = random.randint(1, 0xFFFF)
        self._dh_priv, self._dh_pub = a, A

        payload = build_init_payload(sid, A, self.username)
        await self.transport.send_session(peer, payload)
        print(f"[session:init] sent to {peer}: sid={sid}, A=({A.bit_length()} bits)")

    # ----- send message -----

    async def send_text(self, peer: str, text: str):
        sess = db_get_session(self.storage, peer)
        if not sess:
            await self.start_session_with(peer)
            # wait briefly for session establishment
            for _ in range(50):
                await asyncio.sleep(0.1)
                sess = db_get_session(self.storage, peer)
                if sess:
                    break
            if not sess:
                print(f"[send] waiting for secure session with {peer}; try again shortly")
                return
        seq = int(sess["seq_send"])
        keys = {"K_enc": sess["k_enc_ab"], "K_mac": sess["k_mac_ab"], "IVseed": sess["ivseed_ab"]}
        sid = int(sess["session_id"])
        pt = text.encode("utf-8")
        frame = build_frame(keys, session_id=sid, seq=seq, plaintext=pt)
        await self.transport.send_frame(peer, sid, frame)
        db_store_message(self.storage, peer, "out", sid, seq, pt)
        db_bump_seq_send(self.storage, peer, seq + 1)
        print(f"You: {text}")

    # ----- receive hooks from Transport -----

    async def _on_session(self, from_user: str, payload: bytes):
        # ensure contact record exists; fetch from relay if needed
        if not self.storage.contact_get(from_user):
            try:
                pem = await self.fetch_remote_pubkey(from_user)
                db_upsert_contact(self.storage, from_user, pem)
                print(f"[contacts] auto-imported {from_user}")
            except Exception as exc:
                print(f"[session] missing contact {from_user}: {exc}")
                return

        try:
            obj = parse_session_payload(payload)
        except Exception:
            print(f"[session] bad payload from {from_user}")
            return

        t = obj.get("t"); sid = int(obj.get("sid", 0)); me = obj.get("me", "?")
        dh_b = b64d(obj.get("dh_b64", ""))
        peer_pub = bytes_to_int(dh_b)

        # two branches: we are responder (got INIT) or initiator (got RESP)
        if t == "init":
            # responder flow: we generate our ephemeral, compute shared, derive keys, store session, send RESP
            b, B = dh_gen()
            s_int = dh_shared(b, peer_pub)
            s_bytes = int_to_bytes(s_int)
            AtoB, BtoA = derive_keys(s_bytes, from_user, self.username)  # direction is peer->me & me->peer
            # store session: peer name key
            db_put_session(
                self.storage, from_user, sid,
                Kenc_ab=BtoA["K_enc"], Kmac_ab=BtoA["K_mac"], IVseed_ab=BtoA["IVseed"],  # self -> peer
                Kenc_ba=AtoB["K_enc"], Kmac_ba=AtoB["K_mac"], IVseed_ba=AtoB["IVseed"],  # peer -> self
                seq_send=0, seq_recv_next=0
            )
            # send RESP (our B)
            resp = build_resp_payload(sid, B, self.username)
            await self.transport.send_session(from_user, resp)
            print(f"[session:resp] to={from_user} sid={sid}, derived keys; sent B ({B.bit_length()} bits)")
            return

        if t == "resp":
            # initiator flow: compute shared using our ephemeral 'a'
            if self._dh_priv is None:
                print("[session] got RESP but no pending INIT; ignoring")
                return
            s_int = dh_shared(self._dh_priv, peer_pub)
            s_bytes = int_to_bytes(s_int)
            AtoB, BtoA = derive_keys(s_bytes, self.username, from_user)
            db_put_session(
                self.storage, from_user, sid,
                Kenc_ab=AtoB["K_enc"], Kmac_ab=AtoB["K_mac"], IVseed_ab=AtoB["IVseed"],
                Kenc_ba=BtoA["K_enc"], Kmac_ba=BtoA["K_mac"], IVseed_ba=BtoA["IVseed"],
                seq_send=0, seq_recv_next=0
            )
            self._dh_priv = None; self._dh_pub = None
            print(f"[session:init→ready] with {from_user} sid={sid}, keys installed")
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

        sess = db_get_session(self.storage, from_user)
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
        db_store_message(self.storage, from_user, "in", session_id, seq, pt)
        db_set_seq_recv_next(self.storage, from_user, seq + 1)
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

# ---------- CLI ----------

HELP = """
Type your message and press Enter to send to the active contact.
Commands:
  /rekey                         Force a fresh DH/HKDF with the active contact
  /add <name> <src|@peer>        Import or update a contact key
  /chat <name>                   Switch active contact
  /help                          Show this help text
  /quit                          Exit the client
"""

async def cli_main():
    print("[boot] Phase 5 glue: transport ↔ crypto ↔ storage")
    username = input("Enter your username: ").strip()
    pw = getpass.getpass("Vault passphrase: ")

    client = ClientRuntime(username, pw)
    await client.start()

    async def ensure_contact(contact_name: str) -> str:
        try:
            row = client.storage.contact_get(contact_name)
            if row:
                return contact_name
            pem = await client.fetch_remote_pubkey(contact_name)
            db_upsert_contact(client.storage, contact_name, pem)
            print(f"[contacts] auto-imported {contact_name}")
            return contact_name
        except Exception as exc:
            raise RuntimeError(f"could not load contact '{contact_name}': {exc}")

    loop = asyncio.get_running_loop()

    # simple stdin reader
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, os.fdopen(0, "rb", buffering=0))

    active_contact: Optional[str] = None
    if sys.stdin.isatty():
        while not active_contact:
            try:
                peer = input("Chat with (contact name): ").strip()
            except EOFError:
                break
            if not peer:
                continue
            try:
                active_contact = await ensure_contact(peer)
            except Exception as exc:
                print(f"[chat] {exc}")
                continue
            await client.start_session_with(active_contact)
    else:
        print("[chat] non-interactive stdin detected; type /chat <name> or /add to manage contacts.")

    print(HELP)

    async def prompt_clear():
        if not sys.stdin.isatty():
            return
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    async def clear_input_echo():
        if not sys.stdin.isatty():
            return
        # Move to previous line (where input/prompt was) and clear it
        sys.stdout.write("\033[F\r\033[K")
        sys.stdout.flush()

    async def prompt_render():
        if not sys.stdin.isatty():
            return
        label = "You> " if active_contact else "> "
        sys.stdout.write(label)
        sys.stdout.flush()

    client.register_prompt_hooks(prompt_clear, prompt_render)

    while True:
        if sys.stdin.isatty():
            await prompt_render()
            client._prompt_visible = True
        raw_line = await reader.readline()
        if not raw_line:
            break
        if client._prompt_visible:
            await prompt_clear()
            client._prompt_visible = False
        if sys.stdin.isatty():
            await clear_input_echo()
        line_full = raw_line.decode("utf-8", errors="ignore")
        line = line_full.strip()
        if not line:
            continue
        if line == "/quit":
            break
        if line == "/help":
            print(HELP)
            continue
        if line == "/rekey":
            await client.start_session_with(active_contact, force=True)
            continue
        if line.startswith("/add "):
            try:
                _, name, source = line.split(maxsplit=2)
                if source.startswith("@"):
                    target = source[1:] or name
                    pem = await client.fetch_remote_pubkey(target)
                else:
                    path = os.path.expanduser(source)
                    if not os.path.isfile(path):
                        raise FileNotFoundError(f"{path} not found")
                    with open(path, "rb") as f:
                        pem = f.read()
                db_upsert_contact(client.storage, name, pem)
                print(f"[contacts] upserted {name}")
            except Exception as e:
                print(f"[contacts] error: {e}")
            continue
        if line.startswith("/chat "):
            _, name = line.split(maxsplit=1)
            try:
                active_contact = await ensure_contact(name)
                await client.start_session_with(active_contact)
            except Exception as exc:
                print(f"[chat] {exc}")
            continue
        if line.startswith("/start "):
            _, name = line.split(maxsplit=1)
            await client.start_session_with(name)
            continue
        if line.startswith("/send "):
            try:
                _, name, msg = line.split(maxsplit=2)
            except ValueError:
                print("usage: /send <name> <message>"); continue
            await client.send_text(name, msg)
            continue
        if line.startswith("/"):
            print("Unknown command. Type /help")
            continue

        if not active_contact:
            print("[chat] no active contact. Use /chat <name> first.")
            continue
        await client.send_text(active_contact, line)

    # shutdown
    try:
        if client.transport:
            await client.transport.close()
    finally:
        client.storage.logout()
        print("[bye]")

if __name__ == "__main__":
    asyncio.run(cli_main())


