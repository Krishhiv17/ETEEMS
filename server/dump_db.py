"""
Simple helper to inspect server.db contents (users, devices, queue).

Usage:
    python server/dump_db.py           # default ./server/server.db
    python server/dump_db.py --db /path/to/server.db
"""

import argparse
import base64
import getpass
import hashlib
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

SECURITY_DB_PATH = Path(__file__).with_name("security.db")
PBKDF2_ITER = 200_000
PBKDF2_LEN = 32
SALT_LEN = 16


def print_rows(cur, title: str):
    rows = cur.fetchall()
    print(f"\n== {title} ({len(rows)} rows) ==")
    if not rows:
        return
    cols = [d[0] for d in cur.description]
    print(" | ".join(cols))
    print("-" * (len(" | ".join(cols))))
    for row in rows:
        print(" | ".join(str(val) for val in row))


def _decode_key_material(raw: Optional[str], label: str) -> Optional[bytes]:
    if not raw:
        return None
    raw = raw.strip()
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            key = decoder(raw)
            if key:
                return key
        except Exception:
            continue
    raise RuntimeError(f"Invalid {label}; provide base64 or hex key material.")


def _ensure_security_db() -> sqlite3.Connection:
    conn = sqlite3.connect(SECURITY_DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS admin_auth ("
        "id INTEGER PRIMARY KEY CHECK(id=1), "
        "salt BLOB NOT NULL, "
        "pass_hash BLOB NOT NULL, "
        "created_at INTEGER NOT NULL)"
    )
    conn.commit()
    return conn

def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER, dklen=PBKDF2_LEN)

def _setup_admin_password(conn: sqlite3.Connection):
    print("No admin password set. Please create one for decrypting MAC addresses.")
    while True:
        pw1 = getpass.getpass("New admin password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if not pw1:
            print("Password cannot be empty.")
            continue
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
            continue
        break
    salt = os.urandom(SALT_LEN)
    pw_hash = _hash_password(pw1, salt)
    conn.execute("DELETE FROM admin_auth")
    conn.execute(
        "INSERT INTO admin_auth(id, salt, pass_hash, created_at) VALUES(1, ?, ?, ?)",
        (salt, pw_hash, int(time.time())),
    )
    conn.commit()
    print("Admin password set.")
    return True

def _verify_admin_password(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT salt, pass_hash FROM admin_auth WHERE id=1").fetchone()
    if not row:
        return _setup_admin_password(conn)
    salt, stored_hash = row
    attempt = getpass.getpass("Admin password (for MAC decryption): ")
    if not attempt:
        print("Empty password. Skipping decryption.")
        return False
    derived = _hash_password(attempt, salt)
    if derived != stored_hash:
        print("Invalid password. MACs will remain encrypted.")
        return False
    return True

def decrypt_mac(mac_enc: bytes, admin_key: bytes) -> Optional[str]:
    if not mac_enc or len(mac_enc) < 13:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        print("cryptography AESGCM not available; cannot decrypt MACs.")
        return None
    nonce, ct = mac_enc[:12], mac_enc[12:]
    try:
        pt = AESGCM(admin_key).decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="Dump server database tables.")
    parser.add_argument("--db", default="./server/server.db", help="Path to server.db")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    # Load admin key for MAC decryption (required to see plaintext MACs)
    admin_key_raw = os.environ.get("DEVICE_ADMIN_KEY")
    admin_key = None
    if admin_key_raw:
        try:
            admin_key = _decode_key_material(admin_key_raw, "DEVICE_ADMIN_KEY")
        except Exception as exc:
            print(f"DEVICE_ADMIN_KEY invalid: {exc}. MAC decryption disabled.")
            admin_key = None
    else:
        print("DEVICE_ADMIN_KEY not set; MAC decryption disabled.")

    # Ensure/admin password gating
    admin_password_ok = False
    if admin_key:
        sec_conn = _ensure_security_db()
        try:
            admin_password_ok = _verify_admin_password(sec_conn)
        finally:
            sec_conn.close()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute("SELECT name, rsa_pub_pem, added_at FROM users ORDER BY name")
        print_rows(cur, "users")

        print("\n== devices ==")
        cur = conn.execute(
            "SELECT username, mac_hash, mac_enc, registered_at, last_seen, is_active "
            "FROM devices ORDER BY username, registered_at"
        )
        rows = cur.fetchall()
        print(f"rows: {len(rows)}")
        print("username | mac_hash | mac_plaintext | registered_at | last_seen | is_active")
        print("-" * 72)
        for row in rows:
            mac_plain = None
            if admin_key and admin_password_ok and row["mac_enc"]:
                mac_plain = decrypt_mac(row["mac_enc"], admin_key)
            mac_display = mac_plain or "(locked)"
            print(
                f"{row['username']} | {row['mac_hash']} | {mac_display} | "
                f"{row['registered_at']} | {row['last_seen']} | {row['is_active']}"
            )

        cur = conn.execute(
            "SELECT id, msg_kind, recipient, sender, session_id, ts, length(blob) AS blob_len "
            "FROM queue ORDER BY ts"
        )
        print_rows(cur, "queue")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
