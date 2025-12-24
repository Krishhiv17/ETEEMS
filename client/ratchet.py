from __future__ import annotations
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List

from client.crypto import hkdf_derive, dh_gen, dh_shared

# Bound skipped-message storage and skip window to reduce DoS risk.
MAX_SKIP = 2000
MAX_SKIP_KEYS = 2000
# Trigger a DH ratchet every N sent messages (no protocol change).
DH_RATCHET_INTERVAL = 50


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def hkdf_chain_key_step(chain_key: bytes) -> Tuple[bytes, bytes]:
    out = hkdf_derive(chain_key, info=b"dr-chain", length=64, salt=b"")
    return out[:32], out[32:]


def hkdf_root_key_step(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    out = hkdf_derive(dh_output, info=b"dr-root", length=64, salt=root_key)
    return out[:32], out[32:]


def derive_message_keys(message_key: bytes) -> Dict[str, bytes]:
    out = hkdf_derive(message_key, info=b"dr-msg", length=64, salt=b"")
    return {
        "K_enc": out[:16],
        "K_mac": out[16:48],
        "IVseed": out[48:64],
    }


def _init_chain_keys(shared_secret: bytes, initiator: bool, a_name: str, b_name: str) -> Tuple[bytes, bytes]:
    label = f"dr-init|{a_name}<->{b_name}".encode("utf-8")
    out = hkdf_derive(shared_secret, info=label, length=64, salt=b"")
    ck1 = out[:32]
    ck2 = out[32:64]
    return (ck1, ck2) if initiator else (ck2, ck1)


@dataclass
class DoubleRatchetState:
    root_key: bytes
    sending_chain_key: Optional[bytes]
    receiving_chain_key: Optional[bytes]
    send_msg_num: int = 0
    recv_msg_num: int = 0
    prev_chain_len: int = 0
    dh_sending_priv: Optional[int] = None
    dh_sending_pub: Optional[int] = None
    dh_receiving_pub: Optional[int] = None
    skipped_message_keys: Dict[str, str] = field(default_factory=dict)
    skipped_message_keys_order: List[str] = field(default_factory=list)
    send_dh: bool = False

    def to_dict(self) -> dict:
        return {
            "root_key": _b64e(self.root_key),
            "sending_chain_key": _b64e(self.sending_chain_key) if self.sending_chain_key else None,
            "receiving_chain_key": _b64e(self.receiving_chain_key) if self.receiving_chain_key else None,
            "send_msg_num": self.send_msg_num,
            "recv_msg_num": self.recv_msg_num,
            "prev_chain_len": self.prev_chain_len,
            "dh_sending_priv": self.dh_sending_priv,
            "dh_sending_pub": self.dh_sending_pub,
            "dh_receiving_pub": self.dh_receiving_pub,
            "skipped_message_keys": self.skipped_message_keys,
            "skipped_message_keys_order": self.skipped_message_keys_order,
            "send_dh": self.send_dh,
        }

    @staticmethod
    def from_dict(obj: dict) -> "DoubleRatchetState":
        return DoubleRatchetState(
            root_key=_b64d(obj["root_key"]),
            sending_chain_key=_b64d(obj["sending_chain_key"]) if obj.get("sending_chain_key") else None,
            receiving_chain_key=_b64d(obj["receiving_chain_key"]) if obj.get("receiving_chain_key") else None,
            send_msg_num=int(obj.get("send_msg_num", 0)),
            recv_msg_num=int(obj.get("recv_msg_num", 0)),
            prev_chain_len=int(obj.get("prev_chain_len", 0)),
            dh_sending_priv=obj.get("dh_sending_priv"),
            dh_sending_pub=obj.get("dh_sending_pub"),
            dh_receiving_pub=obj.get("dh_receiving_pub"),
            skipped_message_keys=dict(obj.get("skipped_message_keys", {})),
            skipped_message_keys_order=list(obj.get("skipped_message_keys_order", [])),
            send_dh=bool(obj.get("send_dh", False)),
        )


class DoubleRatchet:
    def __init__(self, state: DoubleRatchetState):
        self.state = state

    @staticmethod
    def initialize(shared_secret: bytes, initiator: bool, a_name: str, b_name: str, dh_priv: int, dh_pub: int, dh_peer: int) -> "DoubleRatchet":
        root_key = hkdf_derive(shared_secret, info=b"dr-root-init", length=32, salt=b"")
        send_ck, recv_ck = _init_chain_keys(shared_secret, initiator, a_name, b_name)
        state = DoubleRatchetState(
            root_key=root_key,
            sending_chain_key=send_ck,
            receiving_chain_key=recv_ck,
            dh_sending_priv=dh_priv,
            dh_sending_pub=dh_pub,
            dh_receiving_pub=dh_peer,
        )
        return DoubleRatchet(state)

    def _store_skipped_key(self, key_id: str, mk: bytes) -> None:
        if key_id in self.state.skipped_message_keys:
            return
        self.state.skipped_message_keys[key_id] = _b64e(mk)
        self.state.skipped_message_keys_order.append(key_id)
        if len(self.state.skipped_message_keys_order) > MAX_SKIP_KEYS:
            oldest = self.state.skipped_message_keys_order.pop(0)
            self.state.skipped_message_keys.pop(oldest, None)

    def _skip_message_keys(self, until: int) -> None:
        if self.state.receiving_chain_key is None:
            return
        if until - self.state.recv_msg_num > MAX_SKIP:
            raise RuntimeError("Too many skipped messages")
        while self.state.recv_msg_num < until:
            ck, mk = hkdf_chain_key_step(self.state.receiving_chain_key)
            self.state.receiving_chain_key = ck
            key_id = f"{self.state.dh_receiving_pub}:{self.state.recv_msg_num}"
            self._store_skipped_key(key_id, mk)
            self.state.recv_msg_num += 1

    def _dh_ratchet(self, new_peer_pub: int) -> None:
        self.state.prev_chain_len = self.state.send_msg_num
        self.state.send_msg_num = 0
        self.state.recv_msg_num = 0
        self.state.dh_receiving_pub = new_peer_pub
        shared = dh_shared(self.state.dh_sending_priv, new_peer_pub)
        rk, recv_ck = hkdf_root_key_step(self.state.root_key, shared.to_bytes((shared.bit_length()+7)//8, "big"))
        self.state.root_key = rk
        self.state.receiving_chain_key = recv_ck
        self.state.send_dh = True

    def ratchet_encrypt(self, plaintext: bytes) -> Tuple[dict, Dict[str, bytes]]:
        if not self.state.send_dh and DH_RATCHET_INTERVAL and self.state.send_msg_num > 0:
            if (self.state.send_msg_num % DH_RATCHET_INTERVAL) == 0:
                self.state.send_dh = True

        if self.state.send_dh:
            priv, pub = dh_gen()
            self.state.dh_sending_priv = priv
            self.state.dh_sending_pub = pub
            shared = dh_shared(priv, self.state.dh_receiving_pub)
            rk, send_ck = hkdf_root_key_step(self.state.root_key, shared.to_bytes((shared.bit_length()+7)//8, "big"))
            self.state.root_key = rk
            self.state.sending_chain_key = send_ck
            self.state.send_dh = False
            dh_pub = pub
        else:
            dh_pub = None

        if self.state.sending_chain_key is None:
            raise RuntimeError("Missing sending chain key")
        ck, mk = hkdf_chain_key_step(self.state.sending_chain_key)
        self.state.sending_chain_key = ck
        msg_num = self.state.send_msg_num
        self.state.send_msg_num += 1
        header = {
            "dh_pub": dh_pub,
            "prev_chain_len": self.state.prev_chain_len,
            "msg_num": msg_num,
        }
        return header, {"message_key": mk}

    def ratchet_decrypt(self, header: dict) -> bytes:
        dh_pub = header.get("dh_pub")
        msg_num = int(header.get("msg_num", 0))

        if dh_pub is not None and dh_pub != self.state.dh_receiving_pub:
            self._dh_ratchet(dh_pub)

        key_id = f"{self.state.dh_receiving_pub}:{msg_num}"
        if key_id in self.state.skipped_message_keys:
            mk = _b64d(self.state.skipped_message_keys.pop(key_id))
            try:
                self.state.skipped_message_keys_order.remove(key_id)
            except ValueError:
                pass
            return mk

        if msg_num < self.state.recv_msg_num:
            raise RuntimeError("Replay or old message")

        self._skip_message_keys(msg_num)
        if self.state.receiving_chain_key is None:
            raise RuntimeError("Missing receiving chain key")
        ck, mk = hkdf_chain_key_step(self.state.receiving_chain_key)
        self.state.receiving_chain_key = ck
        self.state.recv_msg_num += 1
        return mk
