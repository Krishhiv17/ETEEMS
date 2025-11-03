# tests/test_phase4.py
import os, sys, pathlib, random, time, binascii, asyncio
from typing import Optional

# Make "client" and "server" importable
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from client.transport import Transport
from client.config import WS_BASE

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRINT_PREFIX = "[Phase 4]"
CONNECT_TIMEOUT = 15
DELIVER_TIMEOUT = 15

def _hexlim(b: bytes, n: int = 64) -> str:
    hx = binascii.hexlify(b).decode()
    return hx if len(hx) <= n else hx[:n] + f"...(+{len(hx)-n})"

def _gen_priv_pem(bits: int = 2048) -> bytes:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

async def _phase4_run(ws_base: Optional[str] = None):
    ws = (ws_base or WS_BASE).rstrip("/")
    print(f"\n{PRINT_PREFIX} using WS_BASE = {ws}")

    # Make unique usernames to avoid clashes with previous runs on the relay
    suffix = str(int(time.time())) + "-" + str(random.randint(1000, 9999))
    alice_user = "Alice_" + suffix
    bob_user   = "Bob_"   + suffix

    # Generate ephemeral keys for test (you’ll use stored keys in real app)
    alice_priv_pem = _gen_priv_pem()
    bob_priv_pem   = _gen_priv_pem()

    # Queues to capture callbacks
    bob_session_q: asyncio.Queue = asyncio.Queue()
    bob_frame_q:   asyncio.Queue = asyncio.Queue()
    bob_queued_q:  asyncio.Queue = asyncio.Queue()

    # Define Bob's handlers
    async def bob_on_session(from_user: str, payload: bytes):
        print(f"{PRINT_PREFIX} [Bob] SESSION_DELIVER from={from_user} payload={_hexlim(payload)}")
        await bob_session_q.put((from_user, payload))

    async def bob_on_frame(from_user: str, session_id: int, frame: bytes):
        print(f"{PRINT_PREFIX} [Bob] DELIVER from={from_user} sid={session_id} frame={_hexlim(frame)}")
        await bob_frame_q.put((from_user, session_id, frame))

    # Alice (sender) will not receive in this test, but we need a loop that just drains
    async def alice_on_session(_f: str, _p: bytes): pass
    async def alice_on_frame(_f: str, _sid: int, _fr: bytes): pass

    # Construct transports
    alice = Transport(None, alice_user, alice_priv_pem)  # defaults to client.config.WS_BASE
    bob   = Transport(None, bob_user,   bob_priv_pem)

    # Connect both
    print(f"{PRINT_PREFIX} connecting Alice: {alice_user}")
    await asyncio.wait_for(alice.connect(), timeout=CONNECT_TIMEOUT)
    print(f"{PRINT_PREFIX} connecting Bob:   {bob_user}")
    await asyncio.wait_for(bob.connect(), timeout=CONNECT_TIMEOUT)

    # Start receive loops
    bob_loop   = asyncio.create_task(bob.run_receive_loop(bob_on_frame, bob_on_session))
    alice_loop = asyncio.create_task(alice.run_receive_loop(alice_on_frame, alice_on_session))

    # --- 1) SESSION flow (opaque payload) ---
    payload = b"handshake-demo-" + os.urandom(8)
    print(f"{PRINT_PREFIX} [Alice] sending SESSION to Bob; payload={_hexlim(payload)}")
    await alice.send_session(bob_user, payload)
    from_user, got_payload = await asyncio.wait_for(bob_session_q.get(), timeout=DELIVER_TIMEOUT)
    assert from_user == alice_user, "SESSION from unexpected user"
    assert got_payload == payload, "SESSION payload mismatch"
    print(f"{PRINT_PREFIX} SESSION delivered OK")

    # --- 2) Online SEND/DELIVER (frame) ---
    session_id = random.randint(1, 0xFFFF)
    frame = b"\x01\x02ciphertext-demo\x03" + os.urandom(6)
    print(f"{PRINT_PREFIX} [Alice] SEND to Bob; sid={session_id} frame={_hexlim(frame)}")
    await alice.send_frame(bob_user, session_id, frame, mid="m1")
    f_user, f_sid, f_bytes = await asyncio.wait_for(bob_frame_q.get(), timeout=DELIVER_TIMEOUT)
    assert f_user == alice_user, "DELIVER from unexpected user"
    assert f_sid == session_id, "DELIVER session_id mismatch"
    assert f_bytes == frame, "DELIVER frame bytes mismatch"
    print(f"{PRINT_PREFIX} online SEND/DELIVER OK")

    # --- 3) Offline queue test ---
    print(f"{PRINT_PREFIX} closing Bob to simulate offline...")
    await bob.close()
    # give server a moment to notice close
    await asyncio.sleep(0.5)

    queued_sid = random.randint(1, 0xFFFF)
    queued_frame = b"queued-ciphertext-" + os.urandom(8)
    print(f"{PRINT_PREFIX} [Alice] SEND while Bob offline; sid={queued_sid} frame={_hexlim(queued_frame)}")
    await alice.send_frame(bob_user, queued_sid, queued_frame, mid="m2")
    print(f"{PRINT_PREFIX} reconnecting Bob to drain queue...")
    bob = Transport(None, bob_user, bob_priv_pem)  # same identity/username
    await asyncio.wait_for(bob.connect(), timeout=CONNECT_TIMEOUT)
    # start a fresh receive loop for Bob
    bob_frame_q = asyncio.Queue()
    bob_session_q = asyncio.Queue()
    bob_loop = asyncio.create_task(bob.run_receive_loop(
        lambda fu, sid, fr: bob_frame_q.put_nowait((fu, sid, fr)),
        lambda fu, pl: bob_session_q.put_nowait((fu, pl)),
    ))
    # Expect the queued frame as soon as Bob finishes HELLO_OK & server drains
    q_from, q_sid, q_bytes = await asyncio.wait_for(bob_frame_q.get(), timeout=DELIVER_TIMEOUT)
    assert q_from == alice_user, "Queued DELIVER from unexpected user"
    assert q_sid == queued_sid, "Queued DELIVER session_id mismatch"
    assert q_bytes == queued_frame, "Queued DELIVER frame bytes mismatch"
    print(f"{PRINT_PREFIX} offline queue drain OK")

    # Cleanup
    await alice.close()
    await bob.close()
    # cancel tasks quietly
    for task in (alice_loop, bob_loop):
        if not task.done():
            task.cancel()
            try:
                await task
            except Exception:
                pass

    print(f"{PRINT_PREFIX} ✅ Phase 4 transport tests PASSED")

def test_phase4_end_to_end():
    # Allow pytest to run the same async scenario
    asyncio.run(_phase4_run())

if __name__ == "__main__":
    # Allow running as a script for verbose manual runs
    try:
        asyncio.run(_phase4_run())
    except AssertionError as e:
        print(f"{PRINT_PREFIX} FAILED: {e}")
        raise
    except Exception as e:
        print(f"{PRINT_PREFIX} ERROR: {e}")
        raise
