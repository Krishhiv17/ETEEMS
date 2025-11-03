# tests/test_phase2.py
import os
import sys, pathlib, binascii, random

# Ensure project root is on path
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from client.framing import (
    pack_header, unpack_header, derive_iv, build_frame, parse_and_verify_frame,
    BadTag, ReplayError, OutOfOrderError, ShortFrame
)
from client.config import FRAME_VERSION, HEADER_LEN, IV_LEN, TAG_LEN
from client.crypto import hmac_tag, dh_gen, dh_shared, hkdf_derive

# -------- helpers --------
def hexlim(b: bytes, n: int = 80) -> str:
    """Hex string limited to n chars with length info."""
    hx = binascii.hexlify(b).decode()
    return hx if len(hx) <= n else hx[:n] + f"... (+{len(hx)-n} hex chars)"

def fake_keys():
    return {
        "K_enc": os.urandom(16),
        "K_mac": os.urandom(32),
        "IVseed": os.urandom(16),
    }

# -------- baseline tests with prints --------
def test_header_roundtrip():
    print("\n[test_header_roundtrip]")
    flags, sid, seq = 0, 123, 456
    hdr = pack_header(flags=flags, session_id=sid, seq=seq, version=FRAME_VERSION)
    print(f"  header bytes ({len(hdr)}): {hexlim(hdr)}")
    v, f, sid2, seq2 = unpack_header(hdr)
    print(f"  unpacked -> version={v}, flags={f}, session_id={sid2}, seq={seq2}")
    assert (v, f, sid2, seq2) == (FRAME_VERSION, flags, sid, seq)
    print("  OK")

def test_iv_uniqueness():
    print("\n[test_iv_uniqueness]")
    ks = fake_keys()
    ivs = [derive_iv(ks["IVseed"], i) for i in range(5)]
    for i, iv in enumerate(ivs):
        print(f"  IV[{i}] ({len(iv)}): {hexlim(iv)}")
    assert len({iv for iv in ivs}) == 5
    ivs_large = {derive_iv(ks["IVseed"], i) for i in range(1000)}
    assert len(ivs_large) == 1000
    print("  OK (1000 unique IVs)")

def test_etm_tamper_detects():
    print("\n[test_etm_tamper_detects]")
    ks = fake_keys()
    frame = build_frame(ks, session_id=1, seq=0, plaintext=b"hello")
    print(f"  frame len = {len(frame)}")
    header = frame[:HEADER_LEN]
    iv = frame[HEADER_LEN:HEADER_LEN+IV_LEN]
    tag = frame[-TAG_LEN:]
    ct = frame[HEADER_LEN+IV_LEN:-TAG_LEN]
    print(f"  header:  {hexlim(header)}")
    print(f"  iv:      {hexlim(iv)}")
    print(f"  ct:      {hexlim(ct)}")
    print(f"  tag:     {hexlim(tag)}")

    # flip one bit in ciphertext region -> expect BadTag
    tampered = bytearray(frame)
    tampered[HEADER_LEN + IV_LEN + max(0, len(ct)//2 - 1)] ^= 0x01
    try:
        parse_and_verify_frame(ks, bytes(tampered), expected_session_id=1, expected_seq=0)
        assert False, "should have raised BadTag"
    except BadTag:
        print("  OK (tamper detected)")

def test_replay_and_out_of_order():
    print("\n[test_replay_and_out_of_order]")
    ks = fake_keys()
    f0 = build_frame(ks, session_id=7, seq=0, plaintext=b"A")
    _hdr, _pt = parse_and_verify_frame(ks, f0, expected_session_id=7, expected_seq=0)  # ok
    print("  accepted seq=0 (expected=0)")

    # replay same frame when expected=1
    try:
        parse_and_verify_frame(ks, f0, expected_session_id=7, expected_seq=1)
        assert False, "expected ReplayError"
    except ReplayError:
        print("  OK (replay detected)")

    # out-of-order (seq=2 when expected=1)
    f2 = build_frame(ks, session_id=7, seq=2, plaintext=b"C")
    try:
        parse_and_verify_frame(ks, f2, expected_session_id=7, expected_seq=1)
        assert False, "expected OutOfOrderError"
    except OutOfOrderError:
        print("  OK (out-of-order detected)")

# -------- new: full E2E encryption/decryption between two users --------
def test_full_e2e_two_users():
    print("\n[test_full_e2e_two_users]")
    alice_id = b"Alice"
    bob_id   = b"Bob"

    # 1) Ephemeral DH for each side
    a, A = dh_gen()
    b, B = dh_gen()
    print(f"  Alice A = g^a mod p: {str(A)[:40]}... (bits={A.bit_length()})")
    print(f"  Bob   B = g^b mod p: {str(B)[:40]}... (bits={B.bit_length()})")

    s_alice = dh_shared(a, B)
    s_bob   = dh_shared(b, A)
    assert s_alice == s_bob, "DH mismatch"
    s_bytes = s_alice.to_bytes((s_alice.bit_length()+7)//8, "big")
    print("  DH shared secret established (equal on both sides).")

    # 2) HKDF: derive per-direction keys (A->B and B->A)
    info = b"e2e-messenger v1|" + alice_id + b"<->" + bob_id
    okm_len = (16+32+16) * 2  # (K_enc 16, K_mac 32, IVseed 16) * 2 directions
    okm = hkdf_derive(s_bytes, info=info, length=okm_len)

    off = 0
    def take(n):
        nonlocal off
        chunk = okm[off:off+n]; off += n; return chunk

    AtoB = {"K_enc": take(16), "K_mac": take(32), "IVseed": take(16)}
    BtoA = {"K_enc": take(16), "K_mac": take(32), "IVseed": take(16)}

    print(f"  A->B keys: enc={len(AtoB['K_enc'])}B mac={len(AtoB['K_mac'])}B ivseed={len(AtoB['IVseed'])}B")
    print(f"  B->A keys: enc={len(BtoA['K_enc'])}B mac={len(BtoA['K_mac'])}B ivseed={len(BtoA['IVseed'])}B")

    # Use a random session_id to simulate a real conversation
    session_id = random.randint(1, 0xFFFF)
    print(f"  session_id = {session_id}")

    # 3) Alice -> Bob : build, verify, decrypt
    seq_ab = 0
    msg_ab = b"hello Bob, it's Alice"
    frame_ab = build_frame(AtoB, session_id=session_id, seq=seq_ab, plaintext=msg_ab)
    print(f"  [A->B] frame len={len(frame_ab)}")
    header = frame_ab[:HEADER_LEN]
    iv = frame_ab[HEADER_LEN:HEADER_LEN+IV_LEN]
    tag = frame_ab[-TAG_LEN:]
    ct = frame_ab[HEADER_LEN+IV_LEN:-TAG_LEN]
    print(f"    header: {hexlim(header)}")
    print(f"    iv:     {hexlim(iv)}")
    print(f"    ct:     {hexlim(ct)}")
    print(f"    tag:    {hexlim(tag)}")

    (_ver, _flags, sid, seq), pt = parse_and_verify_frame(AtoB, frame_ab, expected_session_id=session_id, expected_seq=seq_ab)
    assert sid == session_id and seq == seq_ab
    assert pt == msg_ab
    print("  [A->B] verified + decrypted OK")

    # 4) Bob -> Alice : build, verify, decrypt
    seq_ba = 0
    msg_ba = b"hi Alice, Bob here!"
    frame_ba = build_frame(BtoA, session_id=session_id, seq=seq_ba, plaintext=msg_ba)
    print(f"  [B->A] frame len={len(frame_ba)}")
    header2 = frame_ba[:HEADER_LEN]
    iv2 = frame_ba[HEADER_LEN:HEADER_LEN+IV_LEN]
    tag2 = frame_ba[-TAG_LEN:]
    ct2 = frame_ba[HEADER_LEN+IV_LEN:-TAG_LEN]
    print(f"    header: {hexlim(header2)}")
    print(f"    iv:     {hexlim(iv2)}")
    print(f"    ct:     {hexlim(ct2)}")
    print(f"    tag:    {hexlim(tag2)}")

    (_ver2, _flags2, sid2, seq2), pt2 = parse_and_verify_frame(BtoA, frame_ba, expected_session_id=session_id, expected_seq=seq_ba)
    assert sid2 == session_id and seq2 == seq_ba
    assert pt2 == msg_ba
    print("  [B->A] verified + decrypted OK")

# -------- runner (so you can `python tests/test_phase2.py`) --------
if __name__ == "__main__":
    try:
        test_header_roundtrip()
        test_iv_uniqueness()
        test_etm_tamper_detects()
        test_replay_and_out_of_order()
        test_full_e2e_two_users()
        print("\nPhase 2 tests OK ✅ (including full A<->B round-trip)")
    except AssertionError as e:
        print("\nAssertion failed:", e)
        raise
    except Exception as e:
        print("\nError:", e)
        raise
