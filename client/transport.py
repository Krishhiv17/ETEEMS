import asyncio, base64, json, re
from typing import Callable, Awaitable, Optional
from client.config import WS_BASE

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------- helpers -----------------

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

def load_private_key_pem(pem_bytes: bytes, passphrase: Optional[bytes] = None):
    return serialization.load_pem_private_key(pem_bytes, password=passphrase)

def private_to_public_pem(priv) -> bytes:
    pub = priv.public_key()
    return pub.public_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)

def sign_pss_sha256(priv, message: bytes) -> bytes:
    return priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def _parse_host_port(url: str) -> tuple[str, int]:
    """
    Accepts ws://host:port, wss://host:port, tcp://host:port, or bare host:port.
    Defaults port to 5088.
    """
    s = url.strip()
    s = re.sub(r'^(ws|wss|tcp)://', '', s)  # strip scheme if present
    if '/' in s:  # drop path like /ws
        s = s.split('/', 1)[0]
    if ':' in s:
        host, port = s.rsplit(':', 1)
        try:
            return host, int(port)
        except:
            pass
    return s, 5088

async def _read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)

async def _read_json(reader: asyncio.StreamReader) -> dict:
    # 4-byte big-endian length prefix
    raw_len = await _read_exactly(reader, 4)
    n = int.from_bytes(raw_len, 'big')
    if n <= 0 or n > 8_388_608:
        raise RuntimeError(f"invalid frame length {n}")
    payload = await _read_exactly(reader, n)
    return json.loads(payload.decode('utf-8'))

async def _write_json(writer: asyncio.StreamWriter, obj: dict):
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    writer.write(len(data).to_bytes(4, 'big') + data)
    await writer.drain()

# ----------------- Transport -----------------

class Transport:
    """
    TCP transport with length-prefixed JSON messages.
    Keeps the same API as before:
        - connect()
        - send_session(to_user, payload: bytes)
        - send_frame(to_user, session_id: int, frame_bytes: bytes, mid: Optional[str] = None)
        - run_receive_loop(on_frame, on_session)
    """

    def __init__(self, ws_base_url: Optional[str], username: str, privkey_pem: bytes, privkey_pass: Optional[str] = None):
        base = ws_base_url or WS_BASE  # example: "ws://127.0.0.1:5088"
        self.host, self.port = _parse_host_port(base)
        self.username = username
        self._priv = load_private_key_pem(privkey_pem, passphrase=None if privkey_pass is None else privkey_pass.encode("utf-8"))
        self._pub_pem = private_to_public_pem(self._priv)
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._online_future: Optional[asyncio.Future] = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        # 1) Receive HELLO_CHALLENGE
        msg = await _read_json(self.reader)
        if msg.get("type") != "HELLO_CHALLENGE":
            raise RuntimeError(f"expected HELLO_CHALLENGE, got {msg}")
        nonce = b64d(msg["nonce_b64"])

        # 2) Respond HELLO with RSA-PSS sig and RSA pubkey
        message = b"HELLO||" + nonce
        sig = sign_pss_sha256(self._priv, message)
        hello = {
            "type": "HELLO",
            "user": self.username,
            "sig_b64": b64e(sig),
            "rsa_pub_pem": self._pub_pem.decode("utf-8"),
        }
        await _write_json(self.writer, hello)

        ok = await _read_json(self.reader)
        if ok.get("type") != "HELLO_OK":
            raise RuntimeError(f"handshake failed: {ok}")
        return True

    async def close(self):
        if self.writer is not None:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.writer = None
            self.reader = None

    async def _send_json(self, obj: dict):
        if not self.writer:
            raise RuntimeError("not connected")
        await _write_json(self.writer, obj)

    async def send_session(self, to_user: str, payload: bytes):
        await self._send_json({"type": "SESSION", "to": to_user, "payload_b64": b64e(payload)})

    async def send_frame(self, to_user: str, session_id: int, frame_bytes: bytes, mid: Optional[str] = None):
        msg = {"type": "SEND", "to": to_user, "session_id": int(session_id), "frame_b64": b64e(frame_bytes)}
        if mid is not None: msg["mid"] = mid
        await self._send_json(msg)

    async def request_pubkey(self, user: str):
        await self._send_json({"type": "PUBKEY_REQUEST", "user": user})

    async def request_online(self) -> list[dict]:
        if self._online_future and not self._online_future.done():
            raise RuntimeError("An /online request is already in flight")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._online_future = fut
        await self._send_json({"type": "ONLINE"})
        return await fut

    async def run_receive_loop(
        self,
        on_frame: Callable[[str, int, bytes], Awaitable[None]],
        on_session: Callable[[str, bytes], Awaitable[None]],
        on_pubkey: Optional[Callable[[dict], Awaitable[None]]] = None,
    ):
        assert self.reader is not None
        while True:
            try:
                msg = await _read_json(self.reader)
            except asyncio.IncompleteReadError:
                break
            except Exception:
                # drop malformed frames and continue
                continue

            t = msg.get("type")
            if t == "DELIVER":
                f = msg["from"]; sid = int(msg["session_id"]); frame = b64d(msg["frame_b64"])
                await on_frame(f, sid, frame)
            elif t == "SESSION_DELIVER":
                f = msg["from"]; payload = b64d(msg["payload_b64"])
                await on_session(f, payload)
            # ACK/QUEUED/SESSION_OK/SESSION_QUEUED/PONG can be handled by caller if desired
            elif t in {"PUBKEY_RESPONSE", "PUBKEY_ERROR"}:
                if on_pubkey:
                    await on_pubkey(msg)
            elif t == "ONLINE_LIST":
                if self._online_future and not self._online_future.done():
                    self._online_future.set_result(msg.get("users", []))
                self._online_future = None
