from __future__ import annotations
import struct

from .config import (
    FRAME_VERSION,
    FLAG_MODE_CTR,
    HEADER_LEN,
    IV_LEN,
    TAG_LEN,
    MAX_FRAME_LEN,
)
from .crypto import aes_ctr_encrypt, aes_ctr_decrypt, hmac_tag, ct_eq

class FrameFormatError(Exception):
    """Base class for frame/format errors."""


class BadVersion(FrameFormatError):
    pass


class ShortFrame(FrameFormatError):
    pass


class OversizedFrame(FrameFormatError):
    pass


class BadTag(FrameFormatError):
    pass


class ReplayError(FrameFormatError):
    """seq < expected"""
    pass


class OutOfOrderError(FrameFormatError):
    """seq > expected (if you choose drop policy)"""
    pass

class UnknownSession(FrameFormatError):
    pass


_HDR_STRUCT = struct.Struct("!BBHI")

RATCHET_VERSION = 0x02
RATCHET_FLAG_DH = 0x01
_RATCHET_HDR_STRUCT = struct.Struct('!BBIIH')


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    l = (n.bit_length() + 7) // 8
    return n.to_bytes(l, 'big')


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')



def pack_header(flags: int, session_id: int, seq: int, version: int = FRAME_VERSION) -> bytes:
    """
    Build the 8-byte header.
    Preconditions:
      - 0 <= flags < 256
      - 0 <= session_id < 2**16
      - 0 <= seq < 2**32
      - version == FRAME_VERSION
    """
    if version != FRAME_VERSION:
        raise BadVersion(f"version {version} != FRAME_VERSION {FRAME_VERSION}")
    if not (0 <= flags < 256):
        raise ValueError("flags out of range")
    if not (0 <= session_id < (1 << 16)):
        raise ValueError("session_id out of range")
    if not (0 <= seq < (1 << 32)):
        raise ValueError("seq out of range")
    return _HDR_STRUCT.pack(version, flags, session_id, seq)

def unpack_header(header_bytes: bytes) -> tuple[int, int, int, int]:
    """
    Parse 8-byte header → (version, flags, session_id, seq)
    """
    if len(header_bytes) != HEADER_LEN:
        raise ShortFrame(f"header length {len(header_bytes)} != {HEADER_LEN}")
    version, flags, session_id, seq = _HDR_STRUCT.unpack(header_bytes)
    if version != FRAME_VERSION:
        raise BadVersion(f"got {version}, expected {FRAME_VERSION}")
    return version, flags, session_id, seq

def derive_iv(ivseed: bytes, seq: int) -> bytes:
    """
    Deterministically derive a unique 16-byte IV for AES-CTR from (ivseed, seq).
    - seq is encoded as 8-byte big-endian for the HMAC input (gives headroom)
    - IV = HMAC(ivseed, seq_be_8)[:16]
    """
    if len(ivseed) < 16:
        # Not strictly required, but we expect a 16-byte seed from HKDF slice
        raise ValueError("ivseed too short; expected >=16 bytes")
    seq_be8 = seq.to_bytes(8, "big")
    return hmac_tag(ivseed, seq_be8)[:IV_LEN]

def build_frame(
            keys_dir: dict[str, bytes],
            session_id: int,
            seq: int,
            plaintext: bytes,
            flags: int = FLAG_MODE_CTR,
        ) -> bytes:
    """
    Build a full EtM frame for a single message (sender → receiver direction).

    keys_dir: {"K_enc": bytes, "K_mac": bytes, "IVseed": bytes}
    session_id: 0..65535 (per-peer)
    seq:        0..2^32-1 (per direction)
    flags:      set mode bit to CTR (default), optionally OR with a rekey flag

    Returns: frame = header || IV || ciphertext || tag
    """
    if plaintext is None:
        plaintext = b""
    header = pack_header(flags=flags, session_id=session_id, seq=seq)
    iv = derive_iv(keys_dir["IVseed"], seq)
    ct = aes_ctr_encrypt(keys_dir["K_enc"], iv, plaintext)
    tag = hmac_tag(keys_dir["K_mac"], header + iv + ct)
    frame = header + iv + ct + tag
    if len(frame) > MAX_FRAME_LEN:
        raise OversizedFrame(f"frame length {len(frame)} > MAX_FRAME_LEN {MAX_FRAME_LEN}")
    return frame

def parse_and_verify_frame(
    keys_dir: dict[str, bytes],
    frame: bytes,
    expected_session_id: int,
    expected_seq: int,
    drop_out_of_order: bool = True,
) -> tuple[tuple[int, int, int, int], bytes]:
    """
    Verify & decrypt a received frame (receiver path).

    Steps:
      1) Quick size checks.
      2) Split header(8) | iv(16) | ct | tag(32).
      3) Recompute tag over (header || iv || ct); constant-time compare.
      4) Unpack header; check session_id.
      5) Replay check: seq vs expected_seq (caller persists expected_seq).
      6) Decrypt AES-CTR with derived iv; return ((ver, flags, sid, seq), plaintext).

    Policy for out-of-order (seq > expected_seq):
      - If drop_out_of_order=True: raise OutOfOrderError.
      - Else: return and let caller decide buffering (not typical for this project).
    """
    if frame is None:
        raise ShortFrame("empty frame")
    n = len(frame)
    min_len = HEADER_LEN + IV_LEN + TAG_LEN
    if n < min_len:
        raise ShortFrame(f"frame length {n} < minimal {min_len}")
    if n > MAX_FRAME_LEN:
        raise OversizedFrame(f"frame length {n} > MAX_FRAME_LEN {MAX_FRAME_LEN}")

    header = frame[0:HEADER_LEN]
    iv = frame[HEADER_LEN : HEADER_LEN + IV_LEN]
    tag = frame[-TAG_LEN:]
    ct = frame[HEADER_LEN + IV_LEN : -TAG_LEN]

    # MAC verify first (EtM)
    exp = hmac_tag(keys_dir["K_mac"], header + iv + ct)
    if not ct_eq(exp, tag):
        raise BadTag("HMAC verification failed")

    ver, flags, sid, seq = unpack_header(header)

    if sid != expected_session_id:
        raise UnknownSession(f"header session_id {sid} != expected {expected_session_id}")

    # Replay / ordering checks (receiver maintains expected_seq)
    if seq < expected_seq:
        raise ReplayError(f"seq {seq} < expected {expected_seq}")
    if seq > expected_seq and drop_out_of_order:
        raise OutOfOrderError(f"seq {seq} > expected {expected_seq}")

    # All good → decrypt
    pt = aes_ctr_decrypt(keys_dir["K_enc"], iv, ct)
    return (ver, flags, sid, seq), pt

# ----- Ratchet frames (v2) -----

def build_ratchet_frame(
    keys_dir: dict[str, bytes],
    msg_num: int,
    prev_chain_len: int,
    plaintext: bytes,
    dh_pub: int | None = None,
) -> bytes:
    if plaintext is None:
        plaintext = b''
    flags = RATCHET_FLAG_DH if dh_pub is not None else 0
    dh_bytes = _int_to_bytes(dh_pub) if dh_pub is not None else b''
    header = _RATCHET_HDR_STRUCT.pack(RATCHET_VERSION, flags, prev_chain_len, msg_num, len(dh_bytes)) + dh_bytes
    iv = derive_iv(keys_dir['IVseed'], msg_num)
    ct = aes_ctr_encrypt(keys_dir['K_enc'], iv, plaintext)
    tag = hmac_tag(keys_dir['K_mac'], header + iv + ct)
    frame = header + iv + ct + tag
    if len(frame) > MAX_FRAME_LEN:
        raise OversizedFrame(f'frame length {len(frame)} > MAX_FRAME_LEN {MAX_FRAME_LEN}')
    return frame


def parse_and_verify_ratchet_frame(
    keys_dir: dict[str, bytes],
    frame: bytes,
) -> tuple[dict, bytes]:
    if frame is None:
        raise ShortFrame('empty frame')
    n = len(frame)
    min_len = _RATCHET_HDR_STRUCT.size + IV_LEN + TAG_LEN
    if n < min_len:
        raise ShortFrame(f'frame length {n} < minimal {min_len}')
    if n > MAX_FRAME_LEN:
        raise OversizedFrame(f'frame length {n} > MAX_FRAME_LEN {MAX_FRAME_LEN}')

    version, flags, prev_chain_len, msg_num, dh_len = _RATCHET_HDR_STRUCT.unpack(frame[:_RATCHET_HDR_STRUCT.size])
    if version != RATCHET_VERSION:
        raise BadVersion(f'got {version}, expected {RATCHET_VERSION}')
    off = _RATCHET_HDR_STRUCT.size
    dh_pub = None
    if dh_len:
        dh_bytes = frame[off:off+dh_len]
        dh_pub = _bytes_to_int(dh_bytes)
        off += dh_len
    iv = frame[off:off+IV_LEN]
    tag = frame[-TAG_LEN:]
    ct = frame[off+IV_LEN:-TAG_LEN]
    exp = hmac_tag(keys_dir['K_mac'], frame[:off] + iv + ct)
    if not ct_eq(exp, tag):
        raise BadTag('HMAC verification failed')
    pt = aes_ctr_decrypt(keys_dir['K_enc'], iv, ct)
    header = {
        'dh_pub': dh_pub,
        'prev_chain_len': prev_chain_len,
        'msg_num': msg_num,
    }
    return header, pt


def parse_ratchet_header(frame: bytes) -> tuple[dict, int]:
    if frame is None or len(frame) < _RATCHET_HDR_STRUCT.size:
        raise ShortFrame('empty frame')
    version, flags, prev_chain_len, msg_num, dh_len = _RATCHET_HDR_STRUCT.unpack(frame[:_RATCHET_HDR_STRUCT.size])
    if version != RATCHET_VERSION:
        raise BadVersion(f'got {version}, expected {RATCHET_VERSION}')
    off = _RATCHET_HDR_STRUCT.size
    dh_pub = None
    if dh_len:
        dh_bytes = frame[off:off+dh_len]
        dh_pub = _bytes_to_int(dh_bytes)
        off += dh_len
    header = {
        'dh_pub': dh_pub,
        'prev_chain_len': prev_chain_len,
        'msg_num': msg_num,
    }
    return header, off
