import hashlib, hmac
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def rsa_generate(passphrase: str):
    """Generating a long-term identity key pair. Private Key is PEM-encrypted"""
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sk_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        BestAvailableEncryption(passphrase.encode())
    )
    pk_pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(pk_pem).hexdigest()
    return sk_pem, pk_pem, fingerprint

def rsa_load_private(sk_pem_encrypted: bytes, passphrase: str):
    return serialization.load_pem_private_key(sk_pem_encrypted, password=passphrase.encode())

def rsa_load_public(pk_pem: bytes):
    return serialization.load_pem_public_key(pk_pem)

def rsa_sign(sk, msg: bytes) -> bytes:
    """RSA-PSS signature over msg with SHA-256."""
    return sk.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify(pk, msg: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH),
                  hashes.SHA256())
        return True
    except Exception:
        return False
    
    
# RFC 3526 Group 14 (2048-bit MODP) prime:
P_HEX = (
 "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
 "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
 "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
 "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
 "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
 "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
 "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
G = 2  # generator

def dh_gen():
    a = int.from_bytes(os.urandom(32), "big")
    A = pow(G, a, P)
    return a, A

def dh_shared(my_priv: int, their_pub: int) -> int:
    if not (2 <= their_pub <= P-2):
        raise ValueError("Invalid DH public value")
    return pow(their_pub, my_priv, P)




def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def hkdf_derive(secret_bytes: bytes, info: bytes, length: int, salt: bytes=b"\x00") -> bytes:
    """HKDF-Extract+Expand with SHA-256 to produce 'length' bytes of key material."""
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(secret_bytes)

def hmac_tag(k_mac: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 tag for arbitrary data."""
    h = chmac.HMAC(k_mac, hashes.SHA256())
    h.update(data)
    return h.finalize()


def aes_ctr_encrypt(k_enc: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CTR encryption. IV must be unique for this key."""
    enc = Cipher(algorithms.AES(k_enc), modes.CTR(iv)).encryptor()
    return enc.update(plaintext) + enc.finalize()

def aes_ctr_decrypt(k_enc: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(k_enc), modes.CTR(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


# --- Derive per-direction keys from the DH shared secret ---
def derive_session_keys(shared_int: int, alice_id: bytes, bob_id: bytes):
    """
    Input:  shared_int from DH, and identities to bind context.
    Output: dict with A->B and B->A keys: K_enc, K_mac, IVseed (16B each for IVseed; 16/32B for AES keys)
    """
    s_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8, "big")
    info = b"e2e-messenger v1|" + alice_id + b"<->" + bob_id
    okm = hkdf_derive(s_bytes, info=info, length=16+32+16 + 16+32+16)  # (enc, mac, iv) * 2

    off = 0
    def take(n):
        nonlocal off
        chunk = okm[off:off+n]; off += n; return chunk

    keys = {
        "AtoB": {
            "K_enc":  take(16),   # AES-128
            "K_mac":  take(32),   # HMAC-SHA256 key
            "IVseed": take(16)    # 128-bit seed to derive per-message IVs
        },
        "BtoA": {
            "K_enc":  take(16),
            "K_mac":  take(32),
            "IVseed": take(16)
        }
    }
    return keys

