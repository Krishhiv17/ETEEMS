# Phase 1 Testing Guide: Login/New Account Screen

This guide will help you test the Phase 1 implementation of the login and account creation screens.

## Prerequisites

1. **Server must be running**: The messaging server needs to be running for the client to connect.
   ```bash
   # In one terminal, start the server
   cd /Volumes/Code-CS/Crypto-Project
   python server/app.py
   ```
   The server should show: `[server] listening on tcp://0.0.0.0:5088`

2. **Clean state (optional)**: If you want to test from scratch, clear existing accounts:
   ```bash
   rm -rf ~/.e2e
   ```

## Running the GUI Application

### Method 1: Direct Python execution
```bash
cd /Volumes/Code-CS/Crypto-Project
python -m client.gui_app
```

### Method 2: Using Python module
```bash
cd /Volumes/Code-CS/Crypto-Project
python client/gui_app.py
```

### Method 3: If you have a built executable
```bash
# If you've built it with PyInstaller
./dist/gui_app
# or on macOS
open dist/gui_app.app
```

## Testing Checklist

### ✅ Test 1: Initial Login Screen Display

**Steps:**
1. Launch the GUI application
2. Observe the initial screen

**Expected Result:**
- You should see a screen with:
  - Title: "E2E Messenger"
  - Subtitle: "Secure End-to-End Encrypted Messaging"
  - Two buttons:
    - "Create New Account"
    - "Login to Existing Account"

**Pass Criteria:** ✅ Initial login screen displays correctly

---

### ✅ Test 2: Create New Account - Happy Path

**Steps:**
1. Click "Create New Account"
2. Enter a username (e.g., "testuser1")
3. Enter a passphrase (at least 8 characters, e.g., "testpass123")
4. Confirm the passphrase (same as above)
5. Click "Create Account"

**Expected Result:**
- Status shows "Creating account..."
- After successful creation, main application window appears
- Status shows "Connected as testuser1"
- Friends, Online Users, and Chat sections are visible

**Pass Criteria:** ✅ Account created successfully, main window appears

---

### ✅ Test 3: Create Account - Validation Tests

#### Test 3a: Username Too Short
**Steps:**
1. Click "Create New Account"
2. Enter username: "ab" (less than 3 characters)
3. Enter passphrase: "testpass123"
4. Confirm passphrase: "testpass123"
5. Click "Create Account"

**Expected Result:**
- Red error message: "Username must be at least 3 characters."
- Account is NOT created
- Stay on create account screen

**Pass Criteria:** ✅ Validation prevents short usernames

#### Test 3b: Invalid Username Characters
**Steps:**
1. Click "Create New Account"
2. Enter username: "test user!" (contains space and special char)
3. Enter passphrase: "testpass123"
4. Confirm passphrase: "testpass123"
5. Click "Create Account"

**Expected Result:**
- Red error message: "Username can only contain letters, numbers, _, -, and ."
- Account is NOT created

**Pass Criteria:** ✅ Invalid characters rejected

#### Test 3c: Passphrase Too Short
**Steps:**
1. Click "Create New Account"
2. Enter username: "testuser2"
3. Enter passphrase: "short" (less than 8 characters)
4. Confirm passphrase: "short"
5. Click "Create Account"

**Expected Result:**
- Red error message: "Passphrase must be at least 8 characters long."
- Account is NOT created

**Pass Criteria:** ✅ Short passphrases rejected

#### Test 3d: Passphrase Mismatch
**Steps:**
1. Click "Create New Account"
2. Enter username: "testuser3"
3. Enter passphrase: "testpass123"
4. Confirm passphrase: "differentpass"
5. Click "Create Account"

**Expected Result:**
- Red error message: "Passphrases do not match."
- Account is NOT created

**Pass Criteria:** ✅ Mismatched passphrases rejected

#### Test 3e: Duplicate Account
**Steps:**
1. Create an account with username "testuser1" (from Test 2)
2. Close and reopen the app
3. Click "Create New Account"
4. Enter username: "testuser1" (same as existing)
5. Enter passphrase: "anypass123"
6. Confirm passphrase: "anypass123"
7. Click "Create Account"

**Expected Result:**
- Red error message: "Account 'testuser1' already exists. Please login instead."
- Account is NOT created

**Pass Criteria:** ✅ Duplicate accounts prevented

---

### ✅ Test 4: Login - Happy Path

**Steps:**
1. After creating account in Test 2, close the app
2. Reopen the app
3. Click "Login to Existing Account"
4. Enter username: "testuser1"
5. Enter passphrase: "testpass123" (the one you used to create)
6. Click "Login"

**Expected Result:**
- Status shows "Connecting..."
- After successful login, main application window appears
- Status shows "Connected as testuser1"
- All your previous data (contacts, etc.) is preserved

**Pass Criteria:** ✅ Login successful, main window appears

---

### ✅ Test 5: Login - Error Cases

#### Test 5a: Non-existent Account
**Steps:**
1. Click "Login to Existing Account"
2. Enter username: "nonexistentuser"
3. Enter passphrase: "anypass123"
4. Click "Login"

**Expected Result:**
- Red error message: "Account 'nonexistentuser' does not exist. Please create a new account."
- Login fails
- Stay on login screen

**Pass Criteria:** ✅ Non-existent account error shown

#### Test 5b: Wrong Passphrase
**Steps:**
1. Click "Login to Existing Account"
2. Enter username: "testuser1" (existing account)
3. Enter passphrase: "wrongpass123" (incorrect)
4. Click "Login"

**Expected Result:**
- Error dialog: "Authentication failed" with message about invalid passphrase
- Login fails
- Stay on login screen

**Pass Criteria:** ✅ Wrong passphrase rejected

#### Test 5c: Empty Fields
**Steps:**
1. Click "Login to Existing Account"
2. Leave username empty
3. Leave passphrase empty
4. Click "Login"

**Expected Result:**
- Red error message: "Username is required." (or "Passphrase is required.")
- Login fails

**Pass Criteria:** ✅ Empty fields validated

---

### ✅ Test 6: Navigation Between Screens

**Steps:**
1. Start at login screen
2. Click "Create New Account" → Should show create account form
3. Click "Back" → Should return to login screen
4. Click "Login to Existing Account" → Should show login form
5. Click "Back" → Should return to login screen

**Expected Result:**
- Smooth transitions between screens
- No errors or crashes
- Back button always returns to login screen

**Pass Criteria:** ✅ Navigation works correctly

---

### ✅ Test 7: Enter Key Support

**Steps:**
1. Click "Create New Account"
2. Fill in all fields
3. Press Enter in the "Confirm" passphrase field

**Expected Result:**
- Account creation is triggered (same as clicking "Create Account" button)

**Steps:**
1. Click "Login to Existing Account"
2. Fill in username and passphrase
3. Press Enter in the passphrase field

**Expected Result:**
- Login is triggered (same as clicking "Login" button)

**Pass Criteria:** ✅ Enter key works in forms

---

### ✅ Test 8: Multiple Accounts

**Steps:**
1. Create account "user1" with passphrase "pass1"
2. Close app
3. Reopen app
4. Create account "user2" with passphrase "pass2"
5. Close app
6. Reopen app
7. Login as "user1" with "pass1"
8. Verify you see user1's data
9. Close app
10. Reopen app
11. Login as "user2" with "pass2"
12. Verify you see user2's data (different from user1)

**Expected Result:**
- Each account has separate data
- Login to different accounts shows correct data
- No data mixing between accounts

**Pass Criteria:** ✅ Multiple accounts work independently

---

### ✅ Test 9: Backward Compatibility - CLI App

**Steps:**
1. Create an account via GUI (e.g., "clitest" with passphrase "clitest123")
2. Close GUI
3. Run CLI app:
   ```bash
   python client/app.py
   ```
4. Enter username: "clitest"
5. Enter passphrase: "clitest123"

**Expected Result:**
- CLI app connects successfully
- Can use CLI commands normally
- Data is shared between GUI and CLI (same account)

**Pass Criteria:** ✅ CLI still works with existing accounts

---

### ✅ Test 10: Error Recovery

**Steps:**
1. Click "Create New Account"
2. Enter invalid data (e.g., short username)
3. See error message
4. Fix the data
5. Try again

**Expected Result:**
- Error messages clear when you fix the issue
- Can retry after errors
- No stuck states

**Pass Criteria:** ✅ Error recovery works

---

## Edge Cases to Test

### Edge Case 1: Very Long Username
- Try creating account with username > 50 characters
- Should either work or show appropriate error

### Edge Case 2: Special Characters in Username
- Test: `test_user`, `test-user`, `test.user`, `test123`
- All should work (valid characters)
- Test: `test@user`, `test user`, `test#user`
- Should fail (invalid characters)

### Edge Case 3: Unicode in Passphrase
- Try passphrase with emoji or special Unicode
- Should work (passphrases can be any characters)

### Edge Case 4: Rapid Clicking
- Rapidly click "Create Account" or "Login" buttons
- Should not create duplicate connections or errors

### Edge Case 5: Server Not Running
- Start GUI without server running
- Try to create account or login
- Should show appropriate connection error

---

## Automated Testing (Optional)

If you want to create automated tests, you can create a test file:

```python
# tests/test_phase1_gui.py
import pytest
import os
import tempfile
import shutil
from client.app import ClientRuntime

def test_account_exists_check():
    # Test check_account_exists
    assert ClientRuntime.check_account_exists("nonexistent") == False
    
def test_account_creation():
    # Test account creation flow
    # (Would need GUI testing framework like pytest-qt or similar)
    pass
```

---

## Troubleshooting

### Issue: "Account already exists" when it shouldn't
**Solution:** Check if `~/.e2e/<username>/client.db` exists. Delete it if testing.

### Issue: GUI doesn't start
**Solution:** 
- Check Python version (needs Python 3.7+)
- Check tkinter is installed: `python -c "import tkinter"`
- On Linux, may need: `sudo apt-get install python3-tk`

### Issue: "Connection failed" errors
**Solution:**
- Ensure server is running
- Check `E2E_WS_BASE` environment variable if set
- Check server address in `client/config.py`

### Issue: Can't see error messages
**Solution:**
- Error messages appear in red text below the form
- Check the status bar at the bottom of main window
- Check console/terminal for detailed errors

---

## Success Criteria Summary

Phase 1 is successful if:
- ✅ Login screen appears on app start
- ✅ Can create new accounts with validation
- ✅ Can login to existing accounts
- ✅ Proper error messages for all failure cases
- ✅ Smooth navigation between screens
- ✅ Main window appears after successful auth
- ✅ CLI app still works (backward compatibility)
- ✅ Multiple accounts work independently

---

## Next Steps After Testing

Once Phase 1 is verified working:
1. Document any issues found
2. Fix any bugs discovered
3. Proceed to Phase 2 (Device Limitation) or Phase 3 (Remove Chat Requests)

---

## Quick Test Script

Here's a quick manual test sequence:

```bash
# 1. Start server (in one terminal)
python server/app.py

# 2. In another terminal, test GUI
python client/gui_app.py

# 3. Test sequence:
#    - Click "Create New Account"
#    - Username: "test1", Pass: "testpass123"
#    - Should see main window
#    - Close app
#    - Reopen app
#    - Click "Login to Existing Account"  
#    - Username: "test1", Pass: "testpass123"
#    - Should see main window with your data
```

Good luck with testing! 🚀

