# tests/test_phase3.py
import os
import sys
import pathlib
import tempfile
import shutil
import binascii
import sqlite3
import traceback

# Ensure project root on path
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from client.storage import Storage

def hexlim(b: bytes, n: int = 80) -> str:
    hx = binascii.hexlify(b).decode()
    return hx if len(hx) <= n else hx[:n] + f"... (+{len(hx)-n} hex chars)"

def test_phase3_end_to_end(tmp_path=None):
    print("\n[Phase 3 end-to-end storage tests]")

    # --- 0) temp data dir + explicit DB path (won't touch ~/.e2e) ---
    if tmp_path is None:
        tmpdir = tempfile.mkdtemp(prefix="e2e_store_")
        cleanup = True
    else:
        tmpdir = str(tmp_path)
        cleanup = False
    test_db = os.path.join(tmpdir, "client.db")
    print(f"  using temp data dir: {tmpdir}")
    print(f"  db path: {test_db}")

    try:
        # --- 1) init schema + first-time vault setup ---
        s = Storage(db_path=test_db)
        s.init_schema()
        print("  schema initialized")

        first_pass = "correct horse battery staple"
        s.first_time_setup(first_pass)
        s.logout()
        print("  vault created and storage closed")

        # --- 2) login (unwrap DEK) ---
        s = Storage(db_path=test_db)
        s.init_schema()
        s.login(first_pass)
        print("  login OK (KEK derived, DEK unwrapped)")

        # --- 3) add contact ---
        name = "Bob"
        fake_pub = b"-----BEGIN PUBLIC KEY-----\nFAKEKEY\n-----END PUBLIC KEY-----\n"
        fingerprint = "deadbeef" * 8
        s.contact_add(name, fake_pub, fingerprint, verified=True)
        row = s.contact_get(name)
        assert row is not None and row["verified"] == 1
        print(f"  contact added: {name}, fp={fingerprint[:16]}...")

        # --- 4) create and store session bundles (encrypted with DEK) ---
        import os as _os
        bundle_ab = {
            "K_enc": _os.urandom(16),
            "K_mac": _os.urandom(32),
            "IVseed": _os.urandom(16),
        }
        bundle_ba = {
            "K_enc": _os.urandom(16),
            "K_mac": _os.urandom(32),
            "IVseed": _os.urandom(16),
        }
        sess_id = 0xBEEF
        s.session_upsert(contact=name, session_id=sess_id,
                         bundle_ab=bundle_ab, bundle_ba=bundle_ba,
                         seq_send=0, seq_recv_next=0)
        print(f"  session upserted (session_id={sess_id})")

        # --- 5) load session back and compare ---
        sess = s.session_get(name)
        assert sess is not None
        assert sess["session_id"] == sess_id
        assert sess["bundle_ab"]["K_enc"] == bundle_ab["K_enc"]
        assert sess["bundle_ab"]["K_mac"] == bundle_ab["K_mac"]
        assert sess["bundle_ab"]["IVseed"] == bundle_ab["IVseed"]
        assert sess["bundle_ba"]["K_enc"] == bundle_ba["K_enc"]
        print("  session decrypt round-trip OK")

        # --- 6) seq counters ---
        send0 = s.seq_get_send(name); assert send0 == 0
        send1 = s.seq_inc_send(name); assert send1 == 1
        recv0 = s.seq_get_recv_next(name); assert recv0 == 0
        s.seq_set_recv_next(name, 1)
        recv1 = s.seq_get_recv_next(name); assert recv1 == 1
        print("  seq counters OK (send: 0->1, recv_next: 0->1)")

        # --- 7) messages: plaintext and encrypted bodies ---
        s.message_add(name, "out", b"hello Bob (plain)", encrypt_body=False)
        s.message_add(name, "in", b"hi Alice (secret)", encrypt_body=True)
        msgs = s.messages_list(name, limit=10, decrypt_bodies=True)
        assert len(msgs) >= 2
        print("  messages stored; showing latest few:")
        for m in msgs[:2]:
            print(f"   - [{m['direction']}] ts={m['ts']} text={m['text']!r}")
        assert any("secret" in (m["text"] or "") for m in msgs), "encrypted body did not decrypt"
        print("  messages list OK (plaintext + decrypted encrypted)")

        # --- 8) tamper test: flip a bit in bundle_ab_ct, expect GCM failure on load ---
        print("  tamper test: flipping 1 bit in bundle_ab_ct...")
        s.conn.commit()
        row = s.conn.execute("SELECT bundle_ab_ct FROM sessions WHERE contact=?", (name,)).fetchone()
        ct = bytearray(row["bundle_ab_ct"])
        ct[len(ct)//2] ^= 0x01  # flip a bit in the middle
        s.conn.execute("UPDATE sessions SET bundle_ab_ct=? WHERE contact=?", (bytes(ct), name))
        s.conn.commit()

        tamper_ok = False
        try:
            _ = s.session_get(name)  # should raise on decrypt
            print("  [WARN] tamper not detected (unexpected)")
        except Exception as e:
            print(f"  tamper detected as expected: {type(e).__name__}: {e}")
            tamper_ok = True
        assert tamper_ok, "expected GCM tag failure after tamper"

        # --- 9) passphrase rotation (re-wrap DEK) ---
        new_pass = "much better passphrase!!"
        s.change_passphrase(old_pass=first_pass, new_pass=new_pass)
        print("  passphrase rotated (DEK re-wrapped)")

        # Re-login with new passphrase (fresh instance)
        s.logout()
        s = Storage(db_path=test_db)
        s.init_schema()
        s.login(new_pass)
        print("  re-login with new pass OK")

        # Session row was tampered; create a clean session to verify decrypt works post-rotation.
        print("  restoring a clean session row post-rotation...")
        s.contact_add(name, fake_pub, fingerprint, verified=True)
        bundle_ab2 = {"K_enc": _os.urandom(16), "K_mac": _os.urandom(32), "IVseed": _os.urandom(16)}
        bundle_ba2 = {"K_enc": _os.urandom(16), "K_mac": _os.urandom(32), "IVseed": _os.urandom(16)}
        s.session_upsert(name, session_id=0xCAFE, bundle_ab=bundle_ab2, bundle_ba=bundle_ba2, seq_send=0, seq_recv_next=0)
        sess2 = s.session_get(name)
        assert sess2["bundle_ab"]["K_enc"] == bundle_ab2["K_enc"]
        print("  post-rotation session decrypt OK")

        s.logout()
        print("\nPhase 3 tests OK ✅")

    except AssertionError as e:
        print("\nAssertion failed:", e)
        traceback.print_exc()
        raise
    except Exception as e:
        print("\nError:", e)
        traceback.print_exc()
        raise
    finally:
        if cleanup:
            try:
                shutil.rmtree(tmpdir)
            except Exception:
                pass

# PyTest entry
def test_pytest_wrapper(tmp_path):
    # Let pytest run in its own tmp dir; pass explicit db_path each time.
    test_phase3_end_to_end(tmp_path=tmp_path)

# Script entry
if __name__ == "__main__":
    test_phase3_end_to_end()
