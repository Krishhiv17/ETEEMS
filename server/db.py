# server/db.py
import os, sqlite3, time
from typing import Optional, List

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  name        TEXT PRIMARY KEY,
  rsa_pub_pem BLOB NOT NULL,
  added_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS queue (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_kind    TEXT NOT NULL CHECK(msg_kind IN ('FRAME','SESSION')),
  recipient   TEXT NOT NULL,
  sender      TEXT NOT NULL,
  session_id  INTEGER,
  blob        BLOB NOT NULL,
  ts          INTEGER NOT NULL,
  FOREIGN KEY(recipient) REFERENCES users(name) ON DELETE CASCADE,
  FOREIGN KEY(sender)    REFERENCES users(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_queue_recipient_ts ON queue(recipient, ts);
"""

class ServerDB:
    def __init__(self, path: str = "./server/server.db"):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- users ----
    def get_user_pub(self, name: str) -> Optional[bytes]:
        r = self.conn.execute("SELECT rsa_pub_pem FROM users WHERE name=?", (name,)).fetchone()
        return None if not r else r["rsa_pub_pem"]

    def register_or_update_user(self, name: str, rsa_pub_pem: bytes):
        self.conn.execute(
            "INSERT INTO users(name, rsa_pub_pem, added_at) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET rsa_pub_pem=excluded.rsa_pub_pem",
            (name, rsa_pub_pem, int(time.time()))
        )
        self.conn.commit()

    # ---- queue ----
    def enqueue(self, kind: str, recipient: str, sender: str, session_id: Optional[int], blob: bytes):
        self.conn.execute(
            "INSERT INTO queue(msg_kind, recipient, sender, session_id, blob, ts) VALUES (?, ?, ?, ?, ?, ?)",
            (kind, recipient, sender, session_id, blob, int(time.time()))
        )
        self.conn.commit()

    def dequeue_all_for(self, recipient: str) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM queue WHERE recipient=? ORDER BY ts ASC", (recipient,)
        ).fetchall()

    def delete_ids(self, ids: List[int]):
        if not ids: return
        q = "DELETE FROM queue WHERE id IN ({})".format(",".join("?"*len(ids)))
        self.conn.execute(q, ids)
        self.conn.commit()

    def close(self):
        self.conn.close()
