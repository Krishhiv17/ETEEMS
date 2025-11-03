# server/app.py
import asyncio, json, os, base64, secrets, signal
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = os.environ.get("E2E_HOST", "0.0.0.0")
PORT = int(os.environ.get("E2E_PORT", "5088"))

# --------------- helpers ----------------

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)

async def read_json(reader: asyncio.StreamReader) -> dict:
    # 4-byte big-endian length + JSON
    raw_len = await read_exactly(reader, 4)
    n = int.from_bytes(raw_len, 'big')
    if n <= 0 or n > 8_388_608:
        raise RuntimeError(f"invalid frame length {n}")
    payload = await read_exactly(reader, n)
    return json.loads(payload.decode('utf-8'))

async def write_json(writer: asyncio.StreamWriter, obj: dict):
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    writer.write(len(data).to_bytes(4, 'big') + data)
    await writer.drain()

def load_public_key_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))

def verify_pss_sha256(pub, message: bytes, sig: bytes) -> bool:
    try:
        pub.verify(
            sig,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def _fmt_addr(addr: Optional[tuple[str, int]]) -> str:
    if not addr:
        return "offline"
    host, port = addr
    return f"{host}:{port}"

# --------------- in-memory directory & queues ----------------

class UserState:
    def __init__(self, username: str):
        self.username = username
        self.writer: Optional[asyncio.StreamWriter] = None
        self.pubkey = None  # cryptography RSAPublicKey
        self.inbox_frames: list[dict[str, Any]] = []     # queued SEND frames
        self.inbox_sessions: list[dict[str, Any]] = []   # queued SESSION payloads
        self.pub_pem_text: Optional[str] = None
        self.peer_addr: Optional[tuple[str, int]] = None

USERS: Dict[str, UserState] = {}  # username -> state

def get_or_create_user(name: str) -> UserState:
    if name not in USERS:
        USERS[name] = UserState(name)
    return USERS[name]

async def send_json(writer: asyncio.StreamWriter, obj: dict):
    await write_json(writer, obj)

# --------------- per-connection handler ----------------

async def handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # 1) Send HELLO_CHALLENGE
    nonce = secrets.token_bytes(32)
    await send_json(writer, {"type": "HELLO_CHALLENGE", "nonce_b64": b64e(nonce)})

    username = None
    try:
        # 2) Expect HELLO with user + signature + RSA pubkey
        hello = await read_json(reader)
        if hello.get("type") != "HELLO":
            await send_json(writer, {"type": "ERR", "reason": "expected HELLO"})
            writer.close(); await writer.wait_closed(); return

        username = hello.get("user")
        sig_b64 = hello.get("sig_b64")
        pub_pem = hello.get("rsa_pub_pem")
        if not username or not sig_b64 or not pub_pem:
            await send_json(writer, {"type": "ERR", "reason": "HELLO fields missing"})
            writer.close(); await writer.wait_closed(); return

        try:
            pub = load_public_key_pem(pub_pem)
        except Exception:
            await send_json(writer, {"type": "ERR", "reason": "bad public key"})
            writer.close(); await writer.wait_closed(); return

        message = b"HELLO||" + nonce
        sig = b64d(sig_b64)
        if not verify_pss_sha256(pub, message, sig):
            await send_json(writer, {"type": "ERR", "reason": "signature verify failed"})
            writer.close(); await writer.wait_closed(); return

        # Register / update user state
        u = get_or_create_user(username)
        u.writer = writer
        u.pubkey = pub
        u.pub_pem_text = pub_pem
        u.peer_addr = writer.get_extra_info("peername")

        print(f"[relay] HELLO from {username}@{_fmt_addr(u.peer_addr)}")

        # HELLO OK
        await send_json(writer, {"type": "HELLO_OK"})
        await asyncio.sleep(0.05)  # give client time to set receive loop

        # Drain queued SESSIONs first
        if u.inbox_sessions:
            for item in u.inbox_sessions:
                await send_json(writer, {
                    "type": "SESSION_DELIVER",
                    "from": item["from"],
                    "payload_b64": item["payload_b64"],
                })
            u.inbox_sessions.clear()

        # Drain queued frames
        if u.inbox_frames:
            for item in u.inbox_frames:
                await send_json(writer, {
                    "type": "DELIVER",
                    "from": item["from"],
                    "session_id": item["session_id"],
                    "frame_b64": item["frame_b64"],
                })
            u.inbox_frames.clear()

        # 3) Main loop: route SESSION / SEND
        while True:
            msg = await read_json(reader)
            t = msg.get("type")

            if t == "PING":
                await send_json(writer, {"type": "PONG"})
                continue

            if t == "PUBKEY_REQUEST":
                target = msg.get("user")
                resp_user = USERS.get(target)
                if resp_user and resp_user.pub_pem_text:
                    await send_json(writer, {
                        "type": "PUBKEY_RESPONSE",
                        "user": target,
                        "rsa_pub_pem": resp_user.pub_pem_text,
                    })
                else:
                    await send_json(writer, {
                        "type": "PUBKEY_ERROR",
                        "user": target,
                        "reason": "unknown user or key not available",
                    })
                continue

            if t == "SESSION":
                to_user = msg.get("to"); payload_b64 = msg.get("payload_b64")
                if not to_user or payload_b64 is None:
                    await send_json(writer, {"type": "ERR", "reason": "SESSION fields missing"})
                    continue
                dest = get_or_create_user(to_user)
                if dest.writer is not None:
                    dest.peer_addr = dest.writer.get_extra_info("peername")
                entry = {"from": username, "payload_b64": payload_b64}
                dest_addr = dest.writer.get_extra_info("peername") if dest.writer else dest.peer_addr
                if dest.writer is not None and not dest.writer.is_closing():
                    await send_json(dest.writer, {"type": "SESSION_DELIVER", **entry})
                    await send_json(writer, {"type": "SESSION_OK"})
                    print(f"[relay] SESSION deliver {username}@{_fmt_addr(u.peer_addr)} -> {to_user}@{_fmt_addr(dest_addr)}")
                else:
                    dest.inbox_sessions.append(entry)
                    await send_json(writer, {"type": "SESSION_QUEUED"})
                    print(f"[relay] SESSION queued {username}@{_fmt_addr(u.peer_addr)} -> {to_user}@{_fmt_addr(dest_addr)}")
                continue

            if t == "SEND":
                to_user = msg.get("to")
                sid = int(msg.get("session_id", 0))
                frame_b64 = msg.get("frame_b64")
                mid = msg.get("mid")
                if not to_user or frame_b64 is None:
                    await send_json(writer, {"type": "ERR", "reason": "SEND fields missing"})
                    continue
                dest = get_or_create_user(to_user)
                if dest.writer is not None:
                    dest.peer_addr = dest.writer.get_extra_info("peername")
                entry = {"from": username, "session_id": sid, "frame_b64": frame_b64}
                dest_addr = dest.writer.get_extra_info("peername") if dest.writer else dest.peer_addr
                payload_len = len(b64d(frame_b64))
                if dest.writer is not None and not dest.writer.is_closing():
                    await send_json(dest.writer, {"type": "DELIVER", **entry})
                    if mid is not None:
                        await send_json(writer, {"type": "ACK", "mid": mid})
                    print(f"[relay] SEND deliver {username}@{_fmt_addr(u.peer_addr)} -> {to_user}@{_fmt_addr(dest_addr)} sid={sid} bytes={payload_len}")
                else:
                    dest.inbox_frames.append(entry)
                    if mid is not None:
                        await send_json(writer, {"type": "QUEUED", "mid": mid})
                    print(f"[relay] SEND queued {username}@{_fmt_addr(u.peer_addr)} -> {to_user}@{_fmt_addr(dest_addr)} sid={sid} bytes={payload_len}")
                continue

            # Unknown types: ignore or send error
    except asyncio.IncompleteReadError:
        pass
    except Exception:
        # swallow unexpected exceptions per-connection to keep server alive
        pass
    finally:
        # mark user offline, keep queues & pubkey
        try:
            if username and username in USERS and USERS[username].writer is writer:
                USERS[username].writer = None
                peer = USERS[username].peer_addr
                print(f"[relay] disconnect {username}@{_fmt_addr(peer)}")
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# --------------- entrypoint ----------------

async def main():
    server = await asyncio.start_server(handle_conn, host=HOST, port=PORT, backlog=100)
    print(f"[server] listening on tcp://{HOST}:{PORT}")
    async with server:
        stop = asyncio.Future()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.cancel)
        try:
            await stop
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    asyncio.run(main())
