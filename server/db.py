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

CREATE TABLE IF NOT EXISTS devices (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL,
  mac_address   TEXT NOT NULL,
  registered_at INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  is_active     INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(username) REFERENCES users(name) ON DELETE CASCADE,
  UNIQUE(username, mac_address)
);

CREATE INDEX IF NOT EXISTS idx_devices_username ON devices(username);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);

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

    # ---- devices (max 2 active per user) ----
    def _active_device_count(self, username: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE username=? AND is_active=1",
            (username,),
        ).fetchone()
        return int(row["c"]) if row else 0

    def register_device(self, username: str, mac_address: str) -> bool:
        """
        Register device if under the limit (2). Returns True if allowed/registered,
        False if limit exceeded.
        """
        now = int(time.time())
        row = self.conn.execute(
            "SELECT is_active FROM devices WHERE username=? AND mac_address=?",
            (username, mac_address),
        ).fetchone()

        # Existing device: just update last_seen and reactivate if needed
        if row:
            is_active = bool(row["is_active"])
            if is_active:
                self.update_device_last_seen(username, mac_address)
                return True
            if self._active_device_count(username) < 2:
                self.conn.execute(
                    "UPDATE devices SET is_active=1, last_seen=? WHERE username=? AND mac_address=?",
                    (now, username, mac_address),
                )
                self.conn.commit()
                return True
            return False

        # New device: enforce limit before insert
        if self._active_device_count(username) >= 2:
            return False

        self.conn.execute(
            "INSERT INTO devices(username, mac_address, registered_at, last_seen, is_active) "
            "VALUES(?, ?, ?, ?, 1)",
            (username, mac_address, now, now),
        )
        self.conn.commit()
        return True

    def is_device_allowed(self, username: str, mac_address: str) -> bool:
        row = self.conn.execute(
            "SELECT is_active FROM devices WHERE username=? AND mac_address=?",
            (username, mac_address),
        ).fetchone()
        if row:
            return bool(row["is_active"])
        # Not registered yet: allowed only if active count < 2
        return self._active_device_count(username) < 2

    def update_device_last_seen(self, username: str, mac_address: str) -> None:
        now = int(time.time())
        self.conn.execute(
            "UPDATE devices SET last_seen=?, is_active=1 WHERE username=? AND mac_address=?",
            (now, username, mac_address),
        )
        self.conn.commit()

    def get_user_devices(self, username: str) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM devices WHERE username=? ORDER BY registered_at ASC",
            (username,),
        ).fetchall()

    def deactivate_device(self, username: str, mac_address: str) -> None:
        self.conn.execute(
            "UPDATE devices SET is_active=0 WHERE username=? AND mac_address=?",
            (username, mac_address),
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
