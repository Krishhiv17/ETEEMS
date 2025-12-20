"""
Simple helper to inspect server.db contents (users, devices, queue).

Usage:
    python server/dump_db.py           # default ./server/server.db
    python server/dump_db.py --db /path/to/server.db
"""

import argparse
import sqlite3
from pathlib import Path


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


def main():
    parser = argparse.ArgumentParser(description="Dump server database tables.")
    parser.add_argument("--db", default="./server/server.db", help="Path to server.db")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT name, rsa_pub_pem, added_at FROM users ORDER BY name")
        print_rows(cur, "users")

        cur = conn.execute(
            "SELECT username, mac_address, registered_at, last_seen, is_active "
            "FROM devices ORDER BY username, registered_at"
        )
        print_rows(cur, "devices")

        cur = conn.execute(
            "SELECT id, msg_kind, recipient, sender, session_id, ts, length(blob) AS blob_len "
            "FROM queue ORDER BY ts"
        )
        print_rows(cur, "queue")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
