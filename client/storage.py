"""
Phase 3: Local storage with at-rest encryption (vault + sessions + messages).

Design:
- A random Data Encryption Key (DEK) encrypts sensitive rows (session bundles, optionally message bodies).
- The DEK is wrapped under a KEK derived from the user's passphrase (PBKDF2-HMAC-SHA256).
- The 'vault' table stores KDF params and the wrapped DEK. No plaintext keys are ever written to disk.

Tables:
- vault:     holds kek_salt, kek_iters, dek_wrapped, dek_nonce (single row)
- contacts:  stores peer public keys and verification status
- sessions:  stores session_id, seq counters (plaintext) + encrypted per-direction key bundles
- messages:  stores history; body can be plaintext OR encrypted with DEK (your choice)

Dependencies: sqlite3 (stdlib), cryptography (AESGCM, PBKDF2HMAC)
"""

from __future__ import annotations
import os, json, base64, sqlite3, time
from typing import Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import (
    HOME_DIR, DB_PATH,
    SQLITE_JOURNAL_MODE, SQLITE_FOREIGN_KEYS,
    KDF_SALT_LEN, KDF_KEY_LEN, KDF_ITERATIONS,
    AD_VAULT, AD_SESSIONS, AD_MESSAGES,
    GCM_NONCE_LEN,
)

# --- Utilities ---
def _ensure_home(path: str = HOME_DIR):
    if path:
        os.makedirs(path, exist_ok=True)

def _now_ts() -> int:
    return int(time.time())

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _serialize_bundle(bundle: Dict[str, bytes]) -> bytes:
    """
    Convert a direction bundle {K_enc, K_mac, IVseed} to bytes using JSON+base64.
    """
    obj = {k: _b64e(v) for k, v in bundle.items()}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")

def _deserialize_bundle(b: bytes) -> Dict[str, bytes]:
    obj = json.loads(b.decode("utf-8"))
    return {k: _b64d(v) for k, v in obj.items()}

# -------------- Storage --------------
class Storage:
    """
    SQLite-backed store with a KEK/DEK envelope for encrypting sensitive fields.

    Typical flow:
      s = Storage()                # creates ~/.e2e, opens DB, applies PRAGMAs
      s.init_schema()              # create tables if missing
      s.first_time_setup(pass)     # creates vault w/ wrapped DEK (once)
      s.login(pass)                # derives KEK, unwraps DEK into memory
    ...
    s.logout()                   # zeroizes KEK/DEK best-effort and closes connection
    """
    def __init__(self, db_path: str = DB_PATH):
        _ensure_home(os.path.dirname(db_path) or HOME_DIR)
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._apply_pragmas()

        # Secrets (in-memory only)
        self._kek: Optional[bytes] = None
        self._dek: Optional[bytes] = None
        
    def _apply_pragmas(self):
        cur = self.conn.cursor()
        cur.execute(f"PRAGMA journal_mode={SQLITE_JOURNAL_MODE};")
        if SQLITE_FOREIGN_KEYS:
            cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()
        
    def init_schema(self):
        cur = self.conn.cursor()

        # Single-row vault for KEK params and wrapped DEK
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vault (
          id           INTEGER PRIMARY KEY CHECK (id=1),
          kek_salt     BLOB NOT NULL,
          kek_iters    INTEGER NOT NULL,
          dek_wrapped  BLOB NOT NULL,
          dek_nonce    BLOB NOT NULL,
          created_at   INTEGER NOT NULL
        );
        """)
        # Enforce single row
        cur.execute("INSERT OR IGNORE INTO vault(id, kek_salt, kek_iters, dek_wrapped, dek_nonce, created_at) VALUES (1, X'', 0, X'', X'', 0);")
        cur.execute("DELETE FROM vault WHERE id<>1;")

        # Contacts
        cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
          name          TEXT PRIMARY KEY,
          rsa_pub_pem   BLOB NOT NULL,
          fingerprint   TEXT NOT NULL,
          verified      INTEGER NOT NULL DEFAULT 0,
          added_at      INTEGER NOT NULL,
          remote_username TEXT
        );
        """)
        try:
            cur.execute("ALTER TABLE contacts ADD COLUMN remote_username TEXT")
        except sqlite3.OperationalError:
            pass

        # Sessions (one per contact)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
          contact             TEXT PRIMARY KEY REFERENCES contacts(name) ON DELETE CASCADE,
          session_id          INTEGER NOT NULL,
          bundle_ab_ct        BLOB NOT NULL,
          bundle_ab_nonce     BLOB NOT NULL,
          bundle_ba_ct        BLOB NOT NULL,
          bundle_ba_nonce     BLOB NOT NULL,
          seq_send            INTEGER NOT NULL,
          seq_recv_next       INTEGER NOT NULL,
          last_rekey_at       INTEGER NOT NULL
        );
        """)

        # Messages (store metadata plaintext; body: plaintext OR encrypted with DEK)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          contact       TEXT NOT NULL REFERENCES contacts(name) ON DELETE CASCADE,
          direction     TEXT NOT NULL CHECK(direction IN ('in','out')),
          ts            INTEGER NOT NULL,
          remote_id     INTEGER,
          session_epoch INTEGER,
          plaintext     TEXT,
          body_ct       BLOB,
          body_nonce    BLOB
        );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_msgs_contact_ts ON messages(contact, ts);")

        self.conn.commit()
        cur.close()

    # ---------- Vault / Login ----------
    
    def first_time_setup(self, passphrase: str):
        """
        Create a wrapped DEK in the vault, if not already initialized.
        Safe to call multiple times: it won't override a non-empty vault.
        """
        cur = self.conn.cursor()
        row = cur.execute("SELECT kek_salt, kek_iters, dek_wrapped FROM vault WHERE id=1").fetchone()
        if row and row["kek_salt"] and row["dek_wrapped"]:
            cur.close()
            return  # already initialized

        # Generate KEK params and DEK
        kek_salt = os.urandom(KDF_SALT_LEN)
        kek_iters = KDF_ITERATIONS
        kek = self._derive_kek(passphrase, kek_salt, kek_iters)
        dek = os.urandom(32)  # AES-256

        # Wrap DEK with KEK using AES-GCM
        aesgcm = AESGCM(kek)
        dek_nonce = os.urandom(GCM_NONCE_LEN)
        dek_wrapped = aesgcm.encrypt(dek_nonce, dek, AD_VAULT)  # tag is appended in ciphertext

        cur.execute("""
            UPDATE vault SET kek_salt=?, kek_iters=?, dek_wrapped=?, dek_nonce=?, created_at=?
            WHERE id=1
        """, (kek_salt, kek_iters, dek_wrapped, dek_nonce, _now_ts()))
        self.conn.commit()
        cur.close()

        # Zeroize local KEK/DEK copies
        self._zeroize(kek)
        self._zeroize(dek)
    
    def login(self, passphrase: str):
        """
        Derive KEK from passphrase and unwrap DEK into memory.
        Must be called before reading/writing encrypted fields.
        """
        row = self.conn.execute("SELECT kek_salt, kek_iters, dek_wrapped, dek_nonce FROM vault WHERE id=1").fetchone()
        if not row or not row["kek_salt"] or not row["dek_wrapped"]:
            raise RuntimeError("Vault not initialized. Call first_time_setup(passphrase) once.")

        kek = self._derive_kek(passphrase, row["kek_salt"], int(row["kek_iters"]))
        aesgcm = AESGCM(kek)
        try:
            dek = aesgcm.decrypt(row["dek_nonce"], row["dek_wrapped"], AD_VAULT)
        except Exception as e:
            raise ValueError("Invalid passphrase (could not unwrap DEK).") from e

        self._kek = kek
        self._dek = dek
        
    def change_passphrase(self, old_pass: str, new_pass: str):
        """
        Re-wrap the existing DEK under a KEK derived from the new passphrase.
        """
        # Unwrap with old
        row = self.conn.execute("SELECT kek_salt, kek_iters, dek_wrapped, dek_nonce FROM vault WHERE id=1").fetchone()
        old_kek = self._derive_kek(old_pass, row["kek_salt"], int(row["kek_iters"]))
        aesgcm = AESGCM(old_kek)
        dek = aesgcm.decrypt(row["dek_nonce"], row["dek_wrapped"], AD_VAULT)

        # Wrap with new
        new_salt = os.urandom(KDF_SALT_LEN)
        new_iters = KDF_ITERATIONS
        new_kek = self._derive_kek(new_pass, new_salt, new_iters)
        aesgcm2 = AESGCM(new_kek)
        new_nonce = os.urandom(GCM_NONCE_LEN)
        new_wrapped = aesgcm2.encrypt(new_nonce, dek, AD_VAULT)

        self.conn.execute("""
            UPDATE vault SET kek_salt=?, kek_iters=?, dek_wrapped=?, dek_nonce=?, created_at=?
            WHERE id=1
        """, (new_salt, new_iters, new_wrapped, new_nonce, _now_ts()))
        self.conn.commit()

        # Update in-memory
        self._zeroize(old_kek)
        self._zeroize(new_kek)
        if self._kek is not None:
            self._zeroize(self._kek)
        if self._dek is not None:
            # keep DEK in memory; user stays logged in
            pass
        self._kek = None  # force re-login or keep it; your call
        
    def logout(self):
        """
        Best-effort zeroization of KEK/DEK and close DB connection.
        """
        if self._kek is not None:
            self._zeroize(self._kek)
            self._kek = None
        if self._dek is not None:
            self._zeroize(self._dek)
            self._dek = None
        self.conn.close()
        
    # ---------- Contacts ----------
    
    def contact_add(
        self,
        name: str,
        rsa_pub_pem: bytes,
        fingerprint: str,
        verified: bool = False,
        remote_username: Optional[str] = None,
    ):
        self.conn.execute("""
            INSERT OR REPLACE INTO contacts(name, rsa_pub_pem, fingerprint, verified, added_at, remote_username)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, rsa_pub_pem, fingerprint, 1 if verified else 0, _now_ts(), remote_username))
        self.conn.commit()

    def contact_get(self, name: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM contacts WHERE name=?", (name,)).fetchone()

    def contact_get_by_remote(self, remote_username: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM contacts WHERE remote_username=?", (remote_username,)).fetchone()

    def contact_verify(self, name: str, verified: bool = True):
        self.conn.execute("UPDATE contacts SET verified=? WHERE name=?", (1 if verified else 0, name))
        self.conn.commit()

    def contact_update_alias(self, old_name: str, new_name: str):
        self.conn.execute("UPDATE contacts SET name=? WHERE name=?", (new_name, old_name))
        self.conn.commit()
        
    # ---------- Sessions (bundles encrypted with DEK) ----------
    
    def session_upsert(
        self,
        contact: str,
        session_id: int,
        bundle_ab: Dict[str, bytes],
        bundle_ba: Dict[str, bytes],
        seq_send: int = 0,
        seq_recv_next: int = 0,
        last_rekey_at: Optional[int] = None,
    ):
        self._require_unlocked()
        if last_rekey_at is None:
            last_rekey_at = _now_ts()

        # Serialize → encrypt with DEK
        ab_bytes = _serialize_bundle(bundle_ab)
        ba_bytes = _serialize_bundle(bundle_ba)

        ab_nonce = os.urandom(GCM_NONCE_LEN)
        ba_nonce = os.urandom(GCM_NONCE_LEN)
        aes = AESGCM(self._dek)
        ab_ct = aes.encrypt(ab_nonce, ab_bytes, AD_SESSIONS)
        ba_ct = aes.encrypt(ba_nonce, ba_bytes, AD_SESSIONS)

        self.conn.execute("""
            INSERT INTO sessions(contact, session_id, bundle_ab_ct, bundle_ab_nonce, bundle_ba_ct, bundle_ba_nonce, seq_send, seq_recv_next, last_rekey_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(contact) DO UPDATE SET
              session_id=excluded.session_id,
              bundle_ab_ct=excluded.bundle_ab_ct,
              bundle_ab_nonce=excluded.bundle_ab_nonce,
              bundle_ba_ct=excluded.bundle_ba_ct,
              bundle_ba_nonce=excluded.bundle_ba_nonce,
              seq_send=excluded.seq_send,
              seq_recv_next=excluded.seq_recv_next,
              last_rekey_at=excluded.last_rekey_at
        """, (contact, session_id, ab_ct, ab_nonce, ba_ct, ba_nonce, seq_send, seq_recv_next, last_rekey_at))
        self.conn.commit()
        
    def session_get(self, contact: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM sessions WHERE contact=?", (contact,)).fetchone()
        if not row:
            return None
        # Decrypt bundles (if unlocked)
        result = {
            "contact": row["contact"],
            "session_id": int(row["session_id"]),
            "seq_send": int(row["seq_send"]),
            "seq_recv_next": int(row["seq_recv_next"]),
            "last_rekey_at": int(row["last_rekey_at"]),
        }
        if self._dek is not None:
            aes = AESGCM(self._dek)
            ab_bytes = aes.decrypt(row["bundle_ab_nonce"], row["bundle_ab_ct"], AD_SESSIONS)
            ba_bytes = aes.decrypt(row["bundle_ba_nonce"], row["bundle_ba_ct"], AD_SESSIONS)
            result["bundle_ab"] = _deserialize_bundle(ab_bytes)
            result["bundle_ba"] = _deserialize_bundle(ba_bytes)
        else:
            result["bundle_ab"] = None
            result["bundle_ba"] = None
        return result
    
    def seq_get_send(self, contact: str) -> int:
        row = self.conn.execute("SELECT seq_send FROM sessions WHERE contact=?", (contact,)).fetchone()
        if not row:
            raise KeyError(f"No session for contact '{contact}'")
        return int(row["seq_send"])

    def seq_inc_send(self, contact: str) -> int:
        cur = self.conn.cursor()
        cur.execute("UPDATE sessions SET seq_send = seq_send + 1 WHERE contact=?", (contact,))
        self.conn.commit()
        new = cur.execute("SELECT seq_send FROM sessions WHERE contact=?", (contact,)).fetchone()
        cur.close()
        return int(new["seq_send"])

    def seq_get_recv_next(self, contact: str) -> int:
        row = self.conn.execute("SELECT seq_recv_next FROM sessions WHERE contact=?", (contact,)).fetchone()
        if not row:
            raise KeyError(f"No session for contact '{contact}'")
        return int(row["seq_recv_next"])

    def seq_set_recv_next(self, contact: str, val: int):
        self.conn.execute("UPDATE sessions SET seq_recv_next=? WHERE contact=?", (val, contact))
        self.conn.commit()
        
    # ---------- Messages (store plaintext or encrypt body) ----------
    
    def message_add(
        self,
        contact: str,
        direction: str,           # 'in' or 'out'
        plaintext: bytes,
        remote_id: Optional[int] = None,
        session_epoch: Optional[int] = None,
        encrypt_body: bool = False,
    ):
        ts = _now_ts()
        if not encrypt_body:
            self.conn.execute("""
                INSERT INTO messages(contact, direction, ts, remote_id, session_epoch, plaintext)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (contact, direction, ts, remote_id, session_epoch, plaintext.decode("utf-8", errors="replace")))
        else:
            self._require_unlocked()
            aes = AESGCM(self._dek)
            nonce = os.urandom(GCM_NONCE_LEN)
            ct = aes.encrypt(nonce, plaintext, AD_MESSAGES)
            self.conn.execute("""
                INSERT INTO messages(contact, direction, ts, remote_id, session_epoch, body_ct, body_nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (contact, direction, ts, remote_id, session_epoch, ct, nonce))
        self.conn.commit()
        
    def messages_list(self, contact: str, limit: int = 100, decrypt_bodies: bool = True) -> list[Dict[str, Any]]:
        rows = self.conn.execute("""
            SELECT * FROM messages WHERE contact=? ORDER BY ts DESC LIMIT ?
        """, (contact, limit)).fetchall()
        out = []
        for r in rows:
            entry = dict(r)
            # Normalize body to 'text' key
            if r["plaintext"] is not None:
                entry["text"] = r["plaintext"]
            elif r["body_ct"] is not None and decrypt_bodies:
                self._require_unlocked()
                aes = AESGCM(self._dek)
                pt = aes.decrypt(r["body_nonce"], r["body_ct"], AD_MESSAGES)
                entry["text"] = pt.decode("utf-8", errors="replace")
            else:
                entry["text"] = None
            out.append(entry)
        return out

    # ---------- Internals ----------
    
    def _derive_kek(self, passphrase: str, salt: bytes, iters: int) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KDF_KEY_LEN, salt=salt, iterations=iters)
        return kdf.derive(passphrase.encode("utf-8"))

    def _require_unlocked(self):
        if self._dek is None:
            raise RuntimeError("Locked: call login(passphrase) first.")
        
    @staticmethod
    def _zeroize(b: Optional[bytes]):
        # Best effort: overwrite a bytearray copy; Python can't guarantee wiping interned bytes
        if b is None:
            return
        try:
            ba = bytearray(b)
            for i in range(len(ba)):
                ba[i] = 0
        except Exception:
            pass
