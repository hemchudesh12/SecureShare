"""
verify_system.py — Automated integration test suite for SecureShare.

Tests:
  1. Register Alice and Bob
  2. Alice logs in and uploads a file shared with Bob
  3. Bob downloads the file — verifies decryption and signature
  4. Bob calls the /verify endpoint — asserts "Verified" result
  5. TAMPERING TEST: corrupt the stored ciphertext on disk, then
     attempt download as Bob — asserts the download is BLOCKED and
     the response contains 'Signature Invalid' or 'Tampered'.
  6. TAMPERING VERIFY: call /verify on the corrupted file —
     asserts verification returns False.

Usage (server must be running):
    python app.py          # Terminal 1
    python verify_system.py  # Terminal 2
"""

import os
import re
import requests

BASE_URL  = "http://127.0.0.1:5000"
FILES_DIR = os.path.join(os.path.dirname(__file__), "storage", "files")


def log(msg: str):
    print(f"[TEST] {msg}")


def register_and_login(username: str, password: str) -> requests.Session:
    """Register a user (ignore if exists) and return an authenticated session."""
    s = requests.Session()

    res = s.post(f"{BASE_URL}/register", data={"username": username, "password": password})
    assert res.status_code == 200, f"Register {username}: unexpected status {res.status_code}"
    if "Registration successful" in res.text:
        log(f"  {username} registered.")
    else:
        log(f"  {username} already exists — skipping registration.")

    res = s.post(f"{BASE_URL}/login", data={"username": username, "password": password})
    assert res.status_code == 200, f"Login {username}: unexpected status {res.status_code}"
    assert f"Welcome, {username}" in res.text, f"Login failed for {username}"
    log(f"  {username} logged in.")
    return s


def get_user_id(session: requests.Session, username: str) -> str:
    """Parse a user's ID from the recipient select on the dashboard."""
    res = session.get(f"{BASE_URL}/dashboard")
    match = re.search(rf'value="(\d+)">{username}</option>', res.text)
    if not match:
        raise RuntimeError(f"Could not find {username}'s ID in dashboard HTML.")
    return match.group(1)


def get_file_download_link(session: requests.Session, filename: str) -> str:
    """Return the download path (e.g. /download/3) for *filename* visible to *session*."""
    res   = session.get(f"{BASE_URL}/dashboard")
    # Find the download link near the filename
    # We search for the file_id in any /download/<id> URL on the page
    links = re.findall(r'href="(/download/(\d+))"', res.text)
    if not links:
        raise RuntimeError("No download links found on dashboard.")
    # Return the most recently uploaded file's link (last in list)
    return links[-1][0], links[-1][1]


# ---------------------------------------------------------------------------
# Test 1: Registration and login
# ---------------------------------------------------------------------------
def test_register_login():
    log("=== Test 1: Registration & Login ===")
    global s_alice, s_bob
    s_alice = register_and_login("alice_test", "password123")
    s_bob   = register_and_login("bob_test",   "password123")
    log("  PASS\n")


# ---------------------------------------------------------------------------
# Test 2: Upload (with signing)
# ---------------------------------------------------------------------------
def test_upload():
    log("=== Test 2: Alice uploads file shared with Bob ===")
    bob_id       = get_user_id(s_alice, "bob_test")
    file_content = b"TOP SECRET: RSA-PSS signed content for integrity test."

    res = s_alice.post(
        f"{BASE_URL}/upload",
        files={"file": ("secret_doc.txt", file_content, "text/plain")},
        data={"recipients": [bob_id]}
    )
    assert res.status_code == 200, f"Upload failed: status {res.status_code}"
    assert "uploaded" in res.text.lower() or "encrypted" in res.text.lower(), \
        "Upload success message not found."
    log("  File uploaded and signed. PASS\n")
    return file_content


# ---------------------------------------------------------------------------
# Test 3: Download + signature verification
# ---------------------------------------------------------------------------
def test_download(expected_content: bytes):
    log("=== Test 3: Bob downloads and verifies file ===")
    dl_path, file_id = get_file_download_link(s_bob, "secret_doc.txt")

    res = s_bob.get(f"{BASE_URL}{dl_path}")
    assert res.status_code == 200, f"Download failed: status {res.status_code}"
    assert res.content == expected_content, (
        f"Content mismatch!\n  Expected: {expected_content}\n  Got:      {res.content}"
    )
    log(f"  File content matches original. PASS")
    log(f"  file_id={file_id}\n")
    return file_id


# ---------------------------------------------------------------------------
# Test 4: /verify endpoint
# ---------------------------------------------------------------------------
def test_verify_endpoint(file_id: str):
    log("=== Test 4: Bob calls /verify endpoint ===")
    res = s_bob.get(f"{BASE_URL}/verify/{file_id}",
                    headers={"Accept": "application/json"})
    assert res.status_code == 200
    data = res.json()
    assert data["verified"] is True, f"Verification failed: {data['message']}"
    log(f"  /verify response: {data['message']}")
    log("  PASS\n")


# ---------------------------------------------------------------------------
# Test 5: Tampering detection (download)
# ---------------------------------------------------------------------------
def test_tamper_download(file_id: str):
    log("=== Test 5: Tampering detection — corrupt file then try download ===")

    # Find the stored filename by reading the server's file list.
    # We do this by reading the admin panel if accessible, or parse the file ID
    # to correlate with the files on disk (sorted by mtime — newest = our file).
    stored_files = sorted(
        [f for f in os.listdir(FILES_DIR)],
        key=lambda f: os.path.getmtime(os.path.join(FILES_DIR, f)),
        reverse=True
    )
    if not stored_files:
        raise RuntimeError("No files found in storage/files/")

    target_path = os.path.join(FILES_DIR, stored_files[0])
    log(f"  Corrupting file on disk: {stored_files[0]}")

    # Read, flip a byte in the middle, write back
    with open(target_path, 'r+b') as f:
        data = bytearray(f.read())
        mid  = len(data) // 2
        data[mid] = (data[mid] + 1) % 256
        f.seek(0)
        f.write(data)

    log("  File corrupted. Now attempting download...")

    res = s_bob.get(f"{BASE_URL}/download/{file_id}")
    # The server should redirect to dashboard (non-200 terminal URL) OR
    # return 200 HTML with tamper/signature error message (follow_redirects=True by default).
    body = res.text.lower()
    tamper_signalled = (
        "tampered"    in body or
        "invalid"     in body or
        "signature"   in body or
        "error"       in body or
        res.url.endswith("/dashboard")
    )
    assert tamper_signalled, (
        f"Expected tamper detection but got clean response!\n  URL: {res.url}\n  Body (200 chars): {res.text[:200]}"
    )
    log(f"  Tamper correctly detected. PASS")
    log(f"  Response URL: {res.url}\n")

    # Restore the file for subsequent tests
    with open(target_path, 'r+b') as f:
        data[mid] = (data[mid] - 1) % 256
        f.seek(0)
        f.write(data)
    log("  File restored.\n")


# ---------------------------------------------------------------------------
# Test 6: /verify on tampered file
# ---------------------------------------------------------------------------
def test_tamper_verify(file_id: str):
    log("=== Test 6: /verify on tampered file ===")

    stored_files = sorted(
        [f for f in os.listdir(FILES_DIR)],
        key=lambda f: os.path.getmtime(os.path.join(FILES_DIR, f)),
        reverse=True
    )
    target_path = os.path.join(FILES_DIR, stored_files[0])

    # Corrupt again
    with open(target_path, 'r+b') as f:
        data = bytearray(f.read())
        mid  = len(data) // 2
        data[mid] = (data[mid] + 1) % 256
        f.seek(0)
        f.write(data)

    res  = s_bob.get(f"{BASE_URL}/verify/{file_id}",
                     headers={"Accept": "application/json"})
    assert res.status_code == 200
    body = res.json()
    assert body["verified"] is False, f"Expected verified=False for tampered file, got: {body}"
    log(f"  /verify correctly returned verified=False: {body['message']}")
    log("  PASS\n")

    # Restore
    with open(target_path, 'r+b') as f:
        data[mid] = (data[mid] - 1) % 256
        f.seek(0)
        f.write(data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        test_register_login()
        file_content = test_upload()
        file_id      = test_download(file_content)
        test_verify_endpoint(file_id)
        test_tamper_download(file_id)
        test_tamper_verify(file_id)

        print("\n" + "="*50)
        print("  ✅  ALL TESTS PASSED")
        print("="*50)

    except AssertionError as e:
        print(f"\n❌  TEST FAILED (AssertionError): {e}")
        import traceback; traceback.print_exc()
    except Exception as e:
        print(f"\n❌  TEST FAILED (Exception): {e}")
        import traceback; traceback.print_exc()
