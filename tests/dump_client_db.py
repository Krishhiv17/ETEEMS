#!/usr/bin/env python3
"""
Inspect a client's local vault: contacts, sessions, messages.

Usage examples:
  python -m tests.dump_client_db --user Krishhiv
  python -m tests.dump_client_db --db ~/.e2e/Diya/client.db
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import pathlib
import sqlite3
import sys
import textwrap
import shutil
import tempfile

from typing import Iterable, Optional, Callable

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client.config import AD_VAULT, AD_MESSAGES

DEFAULT_HOME = os.path.expanduser("~/.e2e")


def locate_db(user: Optional[str], db_path: Optional[str]) -> pathlib.Path:
    if db_path:
        return pathlib.Path(os.path.expanduser(db_path)).resolve()
    if not user:
        raise ValueError("Specify --user or --db.")
    path = pathlib.Path(DEFAULT_HOME, user, "client.db")
    if not path.exists():
        raise FileNotFoundError(f"Client DB not found: {path}")
    return path.resolve()


def fetch_rows(conn: sqlite3.Connection, query: str, params: Iterable = ()) -> list[sqlite3.Row]:
    cur = conn.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    return rows


def create_temp_copy(db_path: pathlib.Path) -> pathlib.Path:
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="e2e_db_dump_"))
    base = db_path.name
    tmp_db = tmp_dir / base
    shutil.copy2(db_path, tmp_db)
    for suffix in ("-wal", "-shm", "-journal"):
        src = db_path.with_name(base + suffix)
        if src.exists():
            shutil.copy2(src, tmp_dir / (base + suffix))
    return tmp_db


def _derive_kek(passphrase: str, salt: bytes, iters: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
    return kdf.derive(passphrase.encode("utf-8"))


def init_message_decryptor(conn: sqlite3.Connection, passphrase: str) -> Callable[[bytes, bytes], bytes]:
    row = conn.execute(
        "SELECT kek_salt, kek_iters, dek_wrapped, dek_nonce FROM vault WHERE id=1"
    ).fetchone()
    if not row or not row["kek_salt"]:
        raise RuntimeError("Vault not initialised; cannot decrypt")
    kek = _derive_kek(passphrase, row["kek_salt"], int(row["kek_iters"]))
    aes_kek = AESGCM(kek)
    try:
        dek = aes_kek.decrypt(row["dek_nonce"], row["dek_wrapped"], AD_VAULT)
    except Exception as exc:
        raise ValueError("Invalid passphrase (unwrap failed)") from exc
    aes_msg = AESGCM(dek)

    def decryptor(nonce: bytes, ct: bytes) -> bytes:
        return aes_msg.decrypt(nonce, ct, AD_MESSAGES)

    return decryptor


def print_contacts(conn: sqlite3.Connection) -> None:
    rows = fetch_rows(
        conn,
        "SELECT name, fingerprint, verified, datetime(added_at, 'unixepoch') AS added_at FROM contacts ORDER BY name",
    )
    if not rows:
        print("Contacts: (none)")
        return
    print("Contacts:")
    for row in rows:
        ver = "✅" if row["verified"] else "❌"
        print(f"  - {row['name']} ({ver}) added {row['added_at']} fingerprint={row['fingerprint']}")


def print_sessions(conn: sqlite3.Connection) -> None:
    rows = fetch_rows(
        conn,
        "SELECT contact, session_id, seq_send, seq_recv_next, datetime(last_rekey_at, 'unixepoch') AS last_rekey_at "
        "FROM sessions ORDER BY contact",
    )
    if not rows:
        print("\nSessions: (none)")
        return
    print("\nSessions:")
    for row in rows:
        print(
            f"  - {row['contact']}: sid={row['session_id']} "
            f"seq_send={row['seq_send']} seq_recv_next={row['seq_recv_next']} "
            f"last_rekey={row['last_rekey_at']}"
        )


def print_messages(
    conn: sqlite3.Connection,
    limit: int,
    contact: Optional[str],
    decrypt_fn: Optional[Callable[[bytes, bytes], bytes]],
    show_encrypted: bool,
) -> None:
    params: list = []
    where = ""
    if contact:
        where = "WHERE contact=? "
        params.append(contact)
    rows = fetch_rows(
        conn,
        f"SELECT contact, direction, remote_id, session_epoch, datetime(ts, 'unixepoch') AS ts, "
        f"plaintext, body_ct, body_nonce "
        f"FROM messages {where}ORDER BY ts DESC LIMIT ?",
        (*params, limit),
    )
    if not rows:
        scope = f"(contact={contact}) " if contact else ""
        print(f"\nMessages {scope}(latest {limit}): (none)")
        return
    scope = f"for {contact} " if contact else ""
    mode_label = "encrypted" if show_encrypted else "decrypted"
    print(f"\nMessages {scope}(latest {limit}) [{mode_label} view]:")
    for row in rows:
        if show_encrypted:
            if row["body_ct"] is not None:
                body = base64.b64encode(row["body_ct"]).decode("ascii")
            elif row["plaintext"] is not None:
                body = textwrap.shorten(row["plaintext"], width=120, placeholder="…") + " (plaintext)"
            else:
                body = "<no data>"
        else:
            text = None
            if row["plaintext"] is not None:
                text = row["plaintext"]
            elif decrypt_fn and row["body_ct"] is not None and row["body_nonce"] is not None:
                try:
                    pt = decrypt_fn(row["body_nonce"], row["body_ct"])
                    text = pt.decode("utf-8", errors="replace")
                except Exception:
                    text = "<decrypt error>"
            else:
                text = "<encrypted>"
            body = textwrap.shorten(text, width=120, placeholder="…")
        arrow = "→" if row["direction"] == "out" else "←"
        seq = row["remote_id"] if row["remote_id"] is not None else "-"
        print(
            f"  - {row['ts']} [{row['contact']}] {arrow} "
            f"sid={row['session_epoch']} seq={seq} text={body}"
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=50, help="Max messages to show (default: 50)")
    parser.add_argument("--db", help="Explicit client.db path (skips username prompt)")
    parser.add_argument("--user", help="Username (only used with --db override)")
    parser.add_argument("--passphrase", help="Vault passphrase (skips prompt if decrypting)")
    parser.add_argument("--contact", help="Which contact conversation to show")
    parser.add_argument("--mode", choices=("encrypted", "decrypted"), help="Choose view mode without prompt")
    args = parser.parse_args(argv)

    if args.db:
        db_path = locate_db(args.user, args.db)
        username = args.user or "(unknown)"
    else:
        username = input("Enter username: ").strip()
        db_path = locate_db(username, None)

    tmp_db = create_temp_copy(db_path)
    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    decrypt_fn: Optional[Callable[[bytes, bytes], bytes]] = None

    mode = args.mode
    if not mode:
        mode_choice = input("View mode ([E]ncrypted/[D]ecrypted)? ").strip().lower()
        mode = "decrypted" if mode_choice.startswith("d") else "encrypted"

    show_encrypted = mode == "encrypted"
    if mode == "decrypted":
        pw = args.passphrase
        if pw is None:
            try:
                pw = getpass.getpass("Vault passphrase: ")
            except (EOFError, KeyboardInterrupt):
                print("\n[warn] passphrase entry cancelled; defaulting to encrypted view.")
                mode = "encrypted"
                show_encrypted = True
                pw = None
            except Exception:
                pw = input("Vault passphrase (echoed): ")
        if pw:
            try:
                decrypt_fn = init_message_decryptor(conn, pw)
                print("Decryptor initialised (message bodies will be decoded).")
            except Exception as exc:
                print(f"[warn] {exc}. Proceeding without decrypting bodies.")
                decrypt_fn = None

    contact = args.contact
    if contact is None:
        contact_input = input("Which contact's messages? (blank for all): ").strip()
        contact = contact_input or None

    try:
        print(f"Loaded vault: {db_path}")
        print_contacts(conn)
        print_sessions(conn)
        print_messages(conn, args.limit, contact, decrypt_fn, show_encrypted)
    finally:
        conn.close()
        shutil.rmtree(tmp_db.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
