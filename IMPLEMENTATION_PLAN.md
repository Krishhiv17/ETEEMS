# Implementation Plan: ETEEMS Enhancements

## Overview
This document outlines the detailed plan for implementing 5 major enhancements to the ETEEMS messaging system:
1. Login/New Account Screen (GUI)
2. Device Limitation System (Server-side)
3. Remove Chat Requests / Auto-Session Establishment
4. Double Ratchet Encryption System
5. Enhanced Chat History Security

---

## Phase 1: Login/New Account Screen (GUI)

### Objective
Add a proper authentication flow to the GUI application with separate screens for account creation and login.

### Current State
- GUI (`client/gui_app.py`) currently has username/passphrase fields directly on main window
- No distinction between new account creation and existing account login
- Vault setup happens automatically in `ClientRuntime.start()`

### Changes Required

#### 1.1 GUI Structure Refactoring
**File: `client/gui_app.py`**

- **Create `LoginWindow` class**:
  - Two buttons: "Create New Account" and "Login to Existing Account"
  - Initial screen shown when app launches
  - No direct access to main chat interface until authenticated

- **Create `CreateAccountWindow` class**:
  - Username input field
  - Passphrase input field (with strength indicator)
  - Confirm passphrase field
  - "Create Account" button
  - Back button to return to login screen
  - Validation: username uniqueness check (query server), passphrase strength requirements

- **Modify `ClientGUI` class**:
  - Remove username/passphrase fields from main window
  - Add `_show_login_screen()` method
  - Add `_show_create_account_screen()` method
  - Add `_show_main_window()` method (current main UI)
  - Modify `connect()` to be called after authentication screen completes
  - Store authentication state (new_account vs login)

#### 1.2 Client Runtime Modifications
**File: `client/app.py`**

- **Modify `ClientRuntime.start()`**:
  - Add optional parameter `is_new_account: bool = False`
  - If `is_new_account=True`, ensure `first_time_setup()` is called before login
  - If `is_new_account=False`, skip `first_time_setup()` and go straight to login
  - Better error handling for invalid passphrase vs missing vault

- **Add `ClientRuntime.check_account_exists(username: str) -> bool`**:
  - Check if `~/.e2e/<username>/client.db` exists
  - Return True if vault file exists, False otherwise

#### 1.3 Account Creation Flow
1. User clicks "Create New Account"
2. GUI shows `CreateAccountWindow`
3. User enters username, passphrase (twice)
4. GUI validates:
   - Username format (alphanumeric + underscore/dash)
   - Passphrase match
   - Passphrase strength (min 8 chars, recommend 12+)
5. GUI calls `ClientRuntime.check_account_exists()` to warn if account exists
6. Create account directory structure
7. Initialize `ClientRuntime` with `is_new_account=True`
8. Call `client.start()` which triggers vault creation
9. On success, transition to main window
10. On failure, show error and return to create account screen

#### 1.4 Login Flow
1. User clicks "Login to Existing Account"
2. GUI shows login form (username + passphrase)
3. Initialize `ClientRuntime` with `is_new_account=False`
4. Call `client.start()` which attempts login
5. On success, transition to main window
6. On failure (wrong passphrase), show error and allow retry
7. On failure (account doesn't exist), suggest creating new account

### Database Schema Changes
**None required** - existing vault structure supports this

### Testing Considerations
- Test account creation with duplicate usernames
- Test login with wrong passphrase
- Test login with non-existent account
- Test passphrase validation (too short, mismatch)
- Test UI transitions between screens

### Estimated Complexity
**Low-Medium** - Mostly UI refactoring, minimal backend changes

---

## Phase 2: Device Limitation System (Server-side)

### Objective
Enforce that each user can only connect from 2 registered MAC addresses. Server tracks and validates device connections.

### Current State
- Server (`server/app.py`) tracks users in-memory only (`USERS` dict)
- No persistent device tracking
- No MAC address extraction or validation
- Server database (`server/db.py`) has basic user table but no device tracking

### Changes Required

#### 2.1 MAC Address Extraction
**File: `server/app.py`**

- **Add `get_mac_address(peer_addr: tuple) -> Optional[str]`**:
  - Extract MAC address from connection
  - **Challenge**: TCP connections don't directly expose MAC addresses
  - **Solution**: Request MAC address from client in HELLO message
  - Client sends MAC address in HELLO payload
  - Server validates format (12 hex chars or XX:XX:XX:XX:XX:XX format)
  - Store normalized format (uppercase, colons)

- **Alternative Approach** (if MAC spoofing is acceptable):
  - Use client-reported MAC address (trusted)
  - Client extracts MAC using platform-specific methods:
    - Linux: `/sys/class/net/*/address` or `ip link`
    - macOS: `ifconfig` or `networksetup`
    - Windows: `getmac` or WMI
  - Client includes MAC in HELLO message

#### 2.2 Server Database Schema Updates
**File: `server/db.py`**

- **Add `devices` table**:
```sql
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
```

- **Add methods to `ServerDB` class**:
  - `register_device(username: str, mac_address: str) -> bool`
    - Returns True if device registered, False if limit exceeded
    - Check count of active devices for user
    - If < 2, add new device
    - If == 2, return False (or allow replacement of oldest inactive device)
  
  - `get_user_devices(username: str) -> List[dict]`
    - Return all devices for user
  
  - `is_device_allowed(username: str, mac_address: str) -> bool`
    - Check if MAC address is registered for user
  
  - `update_device_last_seen(username: str, mac_address: str) -> None`
    - Update last_seen timestamp
  
  - `deactivate_device(username: str, mac_address: str) -> None`
    - Mark device as inactive (for replacement)

#### 2.3 Server Connection Handler Updates
**File: `server/app.py`**

- **Modify `handle_conn()` function**:
  - Extract MAC address from HELLO message
  - After signature verification, check device:
    - If new MAC: call `db.register_device(username, mac_address)`
      - If registration fails (limit exceeded): send `DEVICE_LIMIT_EXCEEDED` error and close connection
    - If existing MAC: call `db.update_device_last_seen(username, mac_address)`
  - Store MAC address in `UserState` object
  - Add device validation before processing any messages

- **Add device limit error handling**:
  - New error type: `{"type": "ERR", "reason": "DEVICE_LIMIT_EXCEEDED", "message": "Maximum 2 devices allowed"}`
  - Client should display user-friendly error

#### 2.4 Client Transport Updates
**File: `client/transport.py`**

- **Add MAC address extraction utility**:
  - `get_local_mac_address() -> str`
  - Platform-specific implementation:
    - Linux: Read from `/sys/class/net/eth0/address` or first active interface
    - macOS: Use `ifconfig` or `networksetup -listallhardwareports`
    - Windows: Use `uuid.getnode()` or WMI query
  - Return normalized format (uppercase with colons)

- **Modify `Transport.connect()`**:
  - Extract MAC address before sending HELLO
  - Include `mac_address` field in HELLO message:
    ```python
    hello = {
        "type": "HELLO",
        "user": self.username,
        "sig_b64": b64e(sig),
        "rsa_pub_pem": self._pub_pem.decode("utf-8"),
        "mac_address": get_local_mac_address(),  # NEW
    }
    ```

- **Handle device limit error**:
  - Catch `DEVICE_LIMIT_EXCEEDED` error in connection flow
  - Raise user-friendly exception for GUI to display

#### 2.5 Device Management UI (Optional Enhancement)
**File: `client/gui_app.py`**

- Add "Manage Devices" section in settings
- Show list of registered devices
- Allow user to remove old devices (requires server API endpoint)
- Show last seen timestamps

### Security Considerations

#### MAC Address Spoofing
- **Risk**: MAC addresses can be spoofed on most systems
- **Mitigation Options**:
  1. **Accept the risk**: This is a convenience feature, not security-critical
  2. **Combine with other factors**: Include IP address, user agent, or hardware fingerprint
  3. **Server-side validation**: Use ARP tables if server is on same network (not practical for internet)
  4. **Client certificate**: Generate device-specific certificate on first registration

#### Recommendation
- Use client-reported MAC address (trusted model)
- Document that this is a convenience feature
- Consider adding "device name" field for user identification
- Implement device removal/replacement mechanism

### Database Migration
- Add migration script to create `devices` table
- Backfill existing users: mark all current connections as "device 1" (if possible)

### Testing Considerations
- Test device registration (first device, second device)
- Test device limit enforcement (third device attempt)
- Test device reconnection (same MAC)
- Test MAC address extraction on different platforms
- Test device replacement (deactivate old, add new)
- Test concurrent connections from same device

### Estimated Complexity
**Medium** - Requires database changes, server logic, client MAC extraction, cross-platform compatibility

---

## Phase 3: Remove Chat Requests / Auto-Session Establishment

### Objective
Eliminate the chat request/accept workflow. Messages should automatically establish sessions if needed, making the system more intuitive.

### Current State
- Chat requests require explicit `/chat <alias>` command or GUI button
- Session establishment requires explicit initiation via `start_session_with()`
- `send_text()` waits for session, but requires manual session start
- Friend requests still exist (this is fine - we're only removing chat requests)

### Changes Required

#### 3.1 Automatic Session Establishment
**File: `client/app.py`**

- **Modify `send_text()` method**:
  - Remove the waiting/retry logic for session establishment
  - If no session exists, automatically call `start_session_with()` in background
  - Queue the message to be sent once session is established
  - Show user-friendly status: "Establishing secure connection..." or similar

- **Add message queueing system**:
  - `_pending_messages: Dict[str, List[dict]]` - queue messages per contact
  - `_session_establishing: Set[str]` - track contacts with sessions in progress
  - When session is ready, flush queued messages
  - Limit queue size (e.g., 50 messages) to prevent memory issues

- **Modify `_on_session()` method**:
  - After session is established (init→resp or resp received), check for queued messages
  - Automatically send queued messages in order
  - Clear queue after successful send

#### 3.2 Remove Chat Request Protocol
**File: `client/app.py`**

- **Remove chat request handlers**:
  - Remove `_handle_chat_request()`
  - Remove `_handle_chat_response()`
  - Remove `send_chat_request()`
  - Remove `respond_chat_request()`
  - Remove `_send_chat_request_common()`
  - Remove `send_chat_request_feedback()`

- **Remove chat request events**:
  - Remove `chat_request` event type
  - Remove `chat_started` event (or repurpose for session established)
  - Remove `chat_declined` event

- **Update SESSION payload handling**:
  - Remove `chat_req` and `chat_resp` message types from `_on_session()`
  - Keep only `init` and `resp` for session establishment
  - Keep `friend_req`, `friend_resp`, `friend_remove` for friend management

#### 3.3 GUI Updates
**File: `client/gui_app.py`**

- **Remove chat request UI elements**:
  - Remove "Send Chat Request" button from friend list
  - Remove chat request dialog/prompt handling
  - Remove `request_chat()` method
  - Remove `_handle_chat_feedback()` method

- **Simplify chat opening**:
  - "Open Chat" button directly opens chat window
  - If no session exists, show "Connecting..." status
  - Automatically establish session when user types first message
  - Show connection status indicator in chat window

- **Update event handlers**:
  - Remove `chat_request` event handling from `_handle_runtime_event()`
  - Remove `chat_started` event handling (or repurpose)
  - Remove `chat_declined` event handling

#### 3.4 Session Establishment Improvements

- **Add session state tracking**:
  - `session_state: Dict[str, str]` - track "none", "establishing", "ready", "error"
  - Update state machine as session progresses
  - Show appropriate UI feedback based on state

- **Handle session failures gracefully**:
  - If session establishment fails, show error to user
  - Allow retry mechanism
  - Don't block UI while establishing session

- **Optimize session reuse**:
  - Check if existing session is still valid before creating new one
  - Only establish new session if current one is expired or invalid

#### 3.5 Backward Compatibility

- **Handle old chat request messages**:
  - If receiving `chat_req` from old client, ignore it (or send error)
  - Log warning about incompatible client version
  - Don't break on unknown message types

### Protocol Changes

**SESSION message types (updated)**:
- `init` - Session initialization (unchanged)
- `resp` - Session response (unchanged)
- `friend_req` - Friend request (unchanged)
- `friend_resp` - Friend response (unchanged)
- `friend_remove` - Remove friend (unchanged)
- ~~`chat_req`~~ - **REMOVED**
- ~~`chat_resp`~~ - **REMOVED**

### User Experience Flow

**Old Flow**:
1. User wants to message friend
2. Click "Send Chat Request"
3. Wait for friend to accept
4. Session established
5. Can send messages

**New Flow**:
1. User wants to message friend
2. Click "Open Chat" or type message
3. Session automatically establishes in background
4. Message sends when session ready
5. No explicit request/accept needed

### Testing Considerations
- Test automatic session establishment on first message
- Test message queueing during session establishment
- Test multiple messages queued before session ready
- Test session establishment failure handling
- Test concurrent session establishment attempts
- Test session reuse (don't re-establish if exists)
- Test backward compatibility with old clients

### Estimated Complexity
**Low-Medium** - Mostly removing code and simplifying flows, but requires careful message queueing logic

---

## Phase 4: Double Ratchet Encryption System

### Objective
Implement the Double Ratchet algorithm (Signal/WhatsApp style) where each message uses a new encryption key, providing forward secrecy and post-compromise security.

### Current State
- Single session key established via Diffie-Hellman
- Keys remain static for entire session
- Rekeying requires explicit `/rekey` command
- No forward secrecy between messages
- Session keys stored encrypted in database

### Double Ratchet Overview

The Double Ratchet combines:
1. **Symmetric-key ratchet**: Each message ratchets the sending key forward
2. **DH ratchet**: Periodic DH key exchanges ratchet the root key
3. **Message keys**: Derived from chain keys for each message
4. **Skipped message keys**: Store keys for out-of-order messages

### Changes Required

#### 4.1 New Crypto Primitives
**File: `client/crypto.py`**

- **Add HKDF chain key derivation**:
  ```python
  def hkdf_chain_key_step(chain_key: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
      """
      Ratchet chain key forward: (next_chain_key, message_key) = HKDF(chain_key)
      Returns: (new_chain_key, message_key)
      """
      # HKDF-Expand with fixed info
      # Output: 64 bytes (32 for chain, 32 for message key)
  ```

- **Add root key derivation**:
  ```python
  def hkdf_root_key_step(root_key: bytes, dh_output: bytes) -> bytes:
      """
      Derive new root key from old root key + DH shared secret
      """
      # HKDF(root_key, dh_output, info="root")
  ```

- **Add message key derivation**:
  ```python
  def derive_message_keys(message_key: bytes) -> Dict[str, bytes]:
      """
      Derive K_enc, K_mac, IVseed from message_key
      Returns: {"K_enc": 16 bytes, "K_mac": 32 bytes, "IVseed": 16 bytes}
      """
  ```

#### 4.2 Double Ratchet State Machine
**File: `client/ratchet.py` (NEW)**

Create new file for Double Ratchet implementation:

- **`DoubleRatchetState` class**:
  ```python
  class DoubleRatchetState:
      # Root key (ratcheted via DH)
      root_key: bytes
      
      # Sending chain (ratcheted per message)
      sending_chain_key: Optional[bytes]
      sending_chain_length: int
      
      # Receiving chain (ratcheted per message)
      receiving_chain_key: Optional[bytes]
      receiving_chain_length: int
      
      # DH key pairs
      dh_sending_keypair: Optional[Tuple[int, int]]  # (private, public)
      dh_receiving_public: Optional[int]
      
      # Skipped message keys (for out-of-order)
      skipped_message_keys: Dict[Tuple[int, int], bytes]  # (chain_length, message_num) -> key
      
      # Header keys (for message authentication)
      sending_header_key: bytes
      receiving_header_key: bytes
  ```

- **`DoubleRatchet` class**:
  ```python
  class DoubleRatchet:
      def __init__(self, state: DoubleRatchetState):
          self.state = state
      
      def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes) -> RatchetMessage:
          """
          Encrypt message with current sending chain
          Ratchets sending chain forward
          Returns: RatchetMessage (header + ciphertext + tag)
          """
      
      def ratchet_decrypt(self, ratchet_msg: RatchetMessage, associated_data: bytes) -> bytes:
          """
          Decrypt message, handling skipped keys for out-of-order
          Ratchets receiving chain forward
          """
      
      def perform_dh_ratchet_step(self, peer_dh_public: int):
          """
          Perform DH ratchet: receive peer's DH public, send our new DH public
          Updates root key and chains
          """
  ```

#### 4.3 Ratchet Message Format
**File: `client/framing.py` (modify)**

- **New frame format**:
  ```
  RatchetMessage = {
      version: u8 (0x02 for ratchet, 0x01 for legacy)
      dh_public: u16 length + bytes (optional, only on DH ratchet)
      prev_chain_length: u32 (for skipped key lookup)
      message_num: u32 (within current chain)
      chain_length: u32 (current chain length)
      ciphertext: variable length
      tag: 32 bytes (HMAC)
  }
  ```

- **Update `build_frame()`**:
  - Check if ratchet session: use `build_ratchet_frame()`
  - Otherwise: use legacy `build_frame()` (for backward compatibility)

- **Update `parse_and_verify_frame()`**:
  - Check version byte
  - Route to `parse_ratchet_frame()` or legacy parser

#### 4.4 Storage Schema Updates
**File: `client/storage.py`**

- **Modify `sessions` table**:
```sql
ALTER TABLE sessions ADD COLUMN ratchet_state BLOB;  -- Serialized DoubleRatchetState
ALTER TABLE sessions ADD COLUMN ratchet_version INTEGER DEFAULT 1;  -- 1=legacy, 2=ratchet
```

- **Update `session_upsert()`**:
  - Accept `ratchet_state: Optional[DoubleRatchetState]`
  - Serialize ratchet state to JSON/bytes
  - Encrypt with DEK before storing

- **Update `session_get()`**:
  - Deserialize ratchet state if present
  - Return ratchet state in session dict

- **Add ratchet state serialization**:
  ```python
  def serialize_ratchet_state(state: DoubleRatchetState) -> bytes:
      # Convert to JSON-serializable dict
      # Encrypt sensitive fields (keys)
  
  def deserialize_ratchet_state(data: bytes) -> DoubleRatchetState:
      # Decrypt and reconstruct state
  ```

#### 4.5 Session Establishment with Ratchet
**File: `client/app.py`**

- **Modify `start_session_with()`**:
  - Initialize `DoubleRatchetState` with:
    - Root key from initial DH exchange
    - Generate initial DH keypair for sending
    - Set up initial chains
  - Store ratchet state in database
  - Send initial DH public in first message

- **Modify `_on_session()` for ratchet**:
  - If receiving `init` with ratchet flag:
    - Initialize receiving ratchet state
    - Generate our DH keypair
    - Perform first DH ratchet step
    - Send `resp` with our DH public
  - If receiving `resp` with ratchet:
    - Complete DH ratchet
    - Mark session as ratchet-enabled

#### 4.6 Message Sending with Ratchet
**File: `client/app.py`**

- **Modify `send_text()`**:
  - Load ratchet state from database
  - If ratchet session:
    - Use `DoubleRatchet.ratchet_encrypt()`
    - Update ratchet state
    - Save updated state to database
  - If legacy session:
    - Use existing `build_frame()`

#### 4.7 Message Receiving with Ratchet
**File: `client/app.py`**

- **Modify `_on_frame()`**:
  - Check frame version
  - If ratchet frame:
    - Load ratchet state
    - Use `DoubleRatchet.ratchet_decrypt()`
    - Handle skipped message keys if out-of-order
    - Update ratchet state
    - Save updated state to database
  - If legacy frame:
    - Use existing `parse_and_verify_frame()`

#### 4.8 DH Ratchet Triggering

- **Automatic DH ratchet**:
  - Trigger DH ratchet every N messages (e.g., 50 messages)
  - Or trigger based on time (e.g., every 24 hours)
  - Include DH public in message header when ratcheting

- **Manual DH ratchet**:
  - Keep `/rekey` command for manual ratcheting
  - Send special message with DH public to trigger ratchet

#### 4.9 Backward Compatibility

- **Legacy session support**:
  - Keep existing session format for old sessions
  - Don't force migration to ratchet
  - Allow mixed-mode (some contacts ratchet, some legacy)

- **Migration path**:
  - Option 1: Migrate on next message exchange
  - Option 2: Explicit migration command
  - Option 3: Migrate on rekey

### Security Properties

- **Forward Secrecy**: Compromised message key doesn't reveal future messages
- **Post-Compromise Security**: After compromise, new DH ratchet restores security
- **Break-in Recovery**: New DH keys provide fresh security
- **Message Ordering**: Skipped keys handle out-of-order delivery

### Testing Considerations
- Test ratchet encryption/decryption
- Test DH ratchet step
- Test skipped message keys (out-of-order)
- Test chain key ratcheting
- Test root key derivation
- Test state persistence (save/load)
- Test backward compatibility with legacy sessions
- Test concurrent ratchet sessions with different contacts
- Test ratchet state recovery after crash

### Estimated Complexity
**High** - Major cryptographic refactoring, new state machine, complex key management, requires thorough testing

---

## Phase 5: Enhanced Chat History Security

### Objective
Improve the security of stored chat history beyond current DEK encryption. Implement per-message encryption keys and secure deletion.

### Current State
- Messages encrypted with DEK (same key for all messages)
- Messages stored with `encrypt_body=True` uses AES-GCM with DEK
- No per-message key derivation
- No secure deletion mechanism
- Message metadata (timestamps, direction) stored in plaintext

### Security Improvements

#### 5.1 Per-Message Key Derivation
**File: `client/storage.py`**

- **Derive message-specific keys**:
  - Use HKDF to derive per-message encryption key from DEK
  - Input: DEK + message_id + contact + timestamp
  - Output: Unique key for each message
  - Even if DEK compromised, attacker needs message metadata to decrypt

- **Update `message_add()`**:
  ```python
  def _derive_message_key(self, contact: str, message_id: int, timestamp: int) -> bytes:
      info = f"message-key|{contact}|{message_id}|{timestamp}".encode()
      return hkdf_derive(self._dek, info=info, length=32)
  ```

- **Encrypt with message-specific key**:
  - Derive key for each message
  - Use AES-GCM with message-specific key
  - Store nonce with message (as before)

#### 5.2 Message Authentication
**File: `client/storage.py`**

- **Add message authentication**:
  - Derive MAC key from message key
  - Compute HMAC over: contact + direction + timestamp + ciphertext
  - Store MAC with message
  - Verify MAC on decryption

- **Update message schema**:
```sql
ALTER TABLE messages ADD COLUMN auth_tag BLOB;  -- HMAC tag for integrity
```

#### 5.3 Secure Deletion
**File: `client/storage.py`**

- **Implement secure delete**:
  - Overwrite message ciphertext with random data before deletion
  - Multiple overwrite passes (3-7 passes)
  - SQLite `VACUUM` to reclaim space (optional, may not help on SSDs)

- **Add `secure_delete_message()`**:
  ```python
  def secure_delete_message(self, message_id: int):
      # Overwrite ciphertext with random data
      # Delete row
      # Optionally VACUUM
  ```

- **Add bulk secure delete**:
  - `secure_delete_contact_messages(contact: str)`
  - `secure_delete_old_messages(days: int)` - auto-delete after N days

#### 5.4 Metadata Protection
**File: `client/storage.py`**

- **Encrypt sensitive metadata**:
  - Encrypt contact name in message table (use contact_id instead)
  - Encrypt timestamps (store encrypted, decrypt on read)
  - Minimize plaintext metadata

- **Update schema**:
```sql
-- Store encrypted contact reference
ALTER TABLE messages ADD COLUMN contact_id_hash BLOB;  -- Hash of contact name
-- Encrypted timestamp
ALTER TABLE messages ADD COLUMN ts_encrypted BLOB;  -- Encrypted timestamp
```

#### 5.5 Key Rotation for Messages
**File: `client/storage.py`**

- **Periodic DEK rotation**:
  - Generate new DEK periodically (e.g., every 90 days)
  - Re-encrypt all messages with new DEK
  - Update vault with new wrapped DEK
  - Keep old DEK temporarily for decryption during migration

- **Add `rotate_dek()` method**:
  - Generate new DEK
  - Decrypt all messages with old DEK
  - Re-encrypt with new DEK
  - Update vault
  - Zeroize old DEK

#### 5.6 Message Indexing (Optional)
**File: `client/storage.py`**

- **Encrypted search index**:
  - Create encrypted searchable index
  - Use deterministic encryption for search terms
  - Trade-off: Searchability vs. security

- **Alternative**: Full-text search only on decrypted messages in memory

#### 5.7 Integration with Double Ratchet

- **Use ratchet message keys for storage**:
  - When using Double Ratchet, derive storage key from ratchet message key
  - Each message encrypted with its own ratchet-derived key
  - Provides additional layer of security

- **Update `message_add()`**:
  - If ratchet session: use ratchet message key for storage encryption
  - Otherwise: use DEK-derived message key

### Implementation Strategy

#### Option A: Incremental Enhancement (Recommended)
1. Add per-message key derivation (Phase 5.1)
2. Add message authentication (Phase 5.2)
3. Add secure deletion (Phase 5.3)
4. Add metadata protection (Phase 5.4)
5. Add DEK rotation (Phase 5.5)

#### Option B: Full Overhaul
- Implement all improvements together
- More disruptive but cleaner final state

### Database Migration

- Add new columns with `ALTER TABLE`
- Migrate existing messages:
  - Re-encrypt with per-message keys
  - Add authentication tags
  - Update metadata

### Testing Considerations
- Test per-message key derivation
- Test message authentication (tamper detection)
- Test secure deletion (verify overwrite)
- Test DEK rotation (re-encryption)
- Test metadata encryption/decryption
- Test backward compatibility (old messages)
- Test performance impact (key derivation overhead)

### Estimated Complexity
**Medium-High** - Requires careful key management, migration strategy, and performance considerations

---

## Implementation Order Recommendation

### Recommended Sequence:
1. **Phase 1: Login/New Account Screen** (Week 1)
   - Foundation for user experience
   - Isolated changes, low risk
   - Immediate UX improvement

2. **Phase 2: Device Limitation** (Week 2)
   - Server-side security feature
   - Independent of other changes
   - Can be tested in isolation

3. **Phase 3: Remove Chat Requests** (Week 3)
   - Simplifies user flow
   - Prepares for ratchet implementation
   - Removes complexity before major crypto changes

4. **Phase 4: Double Ratchet** (Weeks 4-6)
   - Major cryptographic upgrade
   - Most complex change
   - Requires thorough testing
   - Benefits from simplified session flow (Phase 3)

5. **Phase 5: Enhanced Chat History** (Week 7)
   - Can leverage ratchet keys if implemented
   - Final security polish
   - Can be done incrementally

### Alternative Order (if Double Ratchet is priority):
1. Phase 1 (Login Screen)
2. Phase 3 (Remove Chat Requests) - Simplify before ratchet
3. Phase 4 (Double Ratchet) - Core feature
4. Phase 2 (Device Limitation) - Can be done in parallel
5. Phase 5 (Chat History) - Enhance with ratchet keys

---

## Testing Strategy

### Unit Tests
- Each phase should have comprehensive unit tests
- Test cryptographic primitives in isolation
- Test state machines and data structures

### Integration Tests
- Test end-to-end message flow
- Test session establishment
- Test error handling and edge cases

### Security Testing
- Penetration testing for each phase
- Verify cryptographic properties
- Test attack scenarios (replay, MITM, etc.)

### Performance Testing
- Measure overhead of new features
- Test with large message volumes
- Test database performance

---

## Risk Assessment

### High Risk
- **Phase 4 (Double Ratchet)**: Complex cryptographic implementation, high chance of bugs
- **Phase 5 (Chat History)**: Data migration risks, potential data loss

### Medium Risk
- **Phase 2 (Device Limitation)**: Cross-platform MAC extraction, potential compatibility issues
- **Phase 3 (Chat Requests)**: Message queueing logic, edge cases

### Low Risk
- **Phase 1 (Login Screen)**: Mostly UI changes, low impact on core functionality

---

## Migration and Backward Compatibility

### Backward Compatibility Strategy
- Support legacy sessions alongside new features
- Gradual migration path for users
- Version detection in protocol messages

### Data Migration
- Scripts to migrate existing databases
- Backup before migration
- Rollback procedures

---

## Documentation Requirements

### For Each Phase:
1. **Architecture Document**: Design decisions, data structures, algorithms
2. **API Documentation**: Function signatures, parameters, return values
3. **User Guide**: How to use new features
4. **Developer Guide**: How to extend/maintain code
5. **Security Analysis**: Threat model, security properties

---

## Success Criteria

### Phase 1: Login Screen
- ✅ Users can create new accounts
- ✅ Users can login to existing accounts
- ✅ Clear error messages for failures
- ✅ Smooth UI transitions

### Phase 2: Device Limitation
- ✅ Users limited to 2 devices
- ✅ Device registration works cross-platform
- ✅ Clear error messages for limit exceeded
- ✅ Device management UI (optional)

### Phase 3: Remove Chat Requests
- ✅ Messages send automatically without requests
- ✅ Sessions establish transparently
- ✅ Message queueing works correctly
- ✅ No breaking changes for existing users

### Phase 4: Double Ratchet
- ✅ Each message uses new key
- ✅ Forward secrecy maintained
- ✅ Post-compromise security works
- ✅ Out-of-order messages handled
- ✅ Backward compatibility maintained

### Phase 5: Enhanced Chat History
- ✅ Per-message encryption keys
- ✅ Message authentication works
- ✅ Secure deletion implemented
- ✅ Performance acceptable
- ✅ Migration successful

---

## Conclusion

This plan provides a comprehensive roadmap for implementing all 5 enhancements. Each phase is designed to be implementable independently while building toward the final secure, user-friendly messaging system. The recommended order balances risk, complexity, and dependencies.

**Next Steps**:
1. Review and approve this plan
2. Set up development branches for each phase
3. Begin implementation with Phase 1
4. Regular code reviews and testing throughout

