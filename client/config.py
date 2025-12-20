import os
HOME_DIR = os.path.expanduser("~/.e2e")
DB_PATH  = os.path.join(HOME_DIR, "client.db")

# Crypto
FRAME_VERSION = 0x01
FLAG_REKEY = 0x01
FLAG_MODE_CTR = 0x00
HEADER_LEN = 1 + 1 + 2 + 4 # = 8
IV_LEN = 16
TAG_LEN = 32
MAX_FRAME_LEN = 64*1028


# Database
SQLITE_JOURNAL_MODE = "WAL"   # better concurrency & crash safety
SQLITE_FOREIGN_KEYS = True

    # --- KDF parameters for KEK derivation (tune iters for ~200–400ms)
KDF_SALT_LEN  = 16
KDF_KEY_LEN   = 32
KDF_ITERATIONS = 200_000  # PBKDF2-HMAC-SHA256

    # --- AEAD (AES-GCM) associated data labels ---
AD_VAULT     = b"e2e-vault"
AD_SESSIONS  = b"e2e-sessions-v1"
AD_MESSAGES  = b"e2e-messages-v1"

    # --- AES-GCM nonces ---
GCM_NONCE_LEN = 12  # 96-bit as recommended


# Default to localhost for client ↔ server websocket/tcp base.
# Users can override with E2E_WS_BASE if connecting to a remote server.
WS_BASE = os.environ.get("E2E_WS_BASE", "ws://127.0.0.1:5088")
