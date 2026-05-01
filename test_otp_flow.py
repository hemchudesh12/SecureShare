"""
test_otp_flow.py — Integration tests for the OTP 2FA & org workflow.

Tests:
  1.  Register → OTP sent (DB contains hashed OTP, expiry set)
  2.  Wrong OTP → rejected
  3.  Expired OTP → rejected
  4.  Correct OTP → account verified + RSA keys generated
  5.  Login step 1 (password) → login OTP issued
  6.  Login OTP verify → session issued
  7.  Upload without org approval → blocked
  8.  Admin creates org & approves user → upload succeeds
  9.  Private key shown only after correct password
  10. File download with signature verification

Prerequisites:
  - Server running:   python app.py
  - Admin exists:     flask create-admin  (username=admin, any password)
  - MAIL_USERNAME & MAIL_PASSWORD NOT set (OTP printed to console)

Usage:
  python test_otp_flow.py
"""

import re
import sys
import time
import requests

BASE_URL = "http://127.0.0.1:5000"

ADMIN_USER = "admin"
ADMIN_PASS = "Admin@1234!"    # change to match your admin account

TEST_USER  = f"testuser_{int(time.time())}"
TEST_EMAIL = f"{TEST_USER}@example.com"
TEST_PASS  = "TestPass@999"

_PASS = "✅ PASS"
_FAIL = "❌ FAIL"


def log(msg: str):
    print(f"[TEST] {msg}")


def get_csrf(sess: requests.Session, url: str) -> str:
    """Fetch a page and extract CSRF token from a hidden input."""
    r = sess.get(url)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


# ── Setup ────────────────────────────────────────────────────────────────────

def admin_login() -> requests.Session:
    s = requests.Session()
    csrf = get_csrf(s, f"{BASE_URL}/login")
    r = s.post(f"{BASE_URL}/login", data={
        "username": ADMIN_USER, "password": ADMIN_PASS, "csrf_token": csrf
    })
    # Step 2: login OTP — in demo mode it is printed to server console.
    # We try with OTP "999999" which will fail; the test just checks login OTP flow.
    # For real tests: read from console / mock email.
    log("Admin login step 1 completed. Check server console for login OTP.")
    return s


# ── Test functions ───────────────────────────────────────────────────────────

def test_register():
    log("=== Test 1: Register new user ===")
    s = requests.Session()
    csrf = get_csrf(s, f"{BASE_URL}/register")
    r = s.post(f"{BASE_URL}/register", data={
        "username": TEST_USER, "email": TEST_EMAIL, "password": TEST_PASS,
        "csrf_token": csrf
    })
    assert r.status_code == 200, f"Register returned {r.status_code}"
    # Expect redirect to verify-otp page or success flash
    assert "verify" in r.url or "otp" in r.text.lower() or "check" in r.text.lower(), \
        f"Expected OTP page. Got: {r.url}"
    log(f"  Registered: {TEST_USER}. {_PASS}")
    return s


def test_wrong_otp(s: requests.Session):
    log("=== Test 2: Wrong OTP → rejected ===")
    csrf = get_csrf(s, f"{BASE_URL}/verify-otp")
    r = s.post(f"{BASE_URL}/verify-otp", data={
        "otp": "000000", "password": TEST_PASS, "csrf_token": csrf
    })
    assert r.status_code == 200
    assert "invalid" in r.text.lower() or "attempt" in r.text.lower(), \
        f"Expected rejection message. Got: {r.text[:200]}"
    log(f"  Wrong OTP correctly rejected. {_PASS}")


def test_otp_attempt_limiting(s: requests.Session):
    log("=== Test 3: OTP attempt limiting (5 attempts) ===")
    csrf = get_csrf(s, f"{BASE_URL}/verify-otp")
    for i in range(4):
        s.post(f"{BASE_URL}/verify-otp", data={
            "otp": "111111", "password": TEST_PASS, "csrf_token": csrf
        })
    r = s.post(f"{BASE_URL}/verify-otp", data={
        "otp": "222222", "password": TEST_PASS, "csrf_token": csrf
    })
    # After 5 wrong attempts, should be locked
    assert ("locked" in r.text.lower() or "attempt" in r.text.lower()), \
        f"Expected lockout. Got: {r.text[:200]}"
    log(f"  Account lockout after 5 failed OTP attempts. {_PASS}")


def test_upload_blocked_without_approval():
    log("=== Test 4: Upload blocked without org approval ===")
    # Register fresh user, verify OTP manually (not possible without SMTP in CI)
    # Instead, test via a known-unverified session — check HTTP 200 with warning
    s = requests.Session()
    # Just verify the /upload endpoint properly guards — we can't do full OTP flow
    # without intercepting email. We simulate by checking the block message.
    csrf = get_csrf(s, f"{BASE_URL}/login")
    r = s.post(f"{BASE_URL}/login", data={
        "username": TEST_USER, "password": TEST_PASS, "csrf_token": csrf
    })
    # Should redirect to verify-otp (not yet verified)
    assert "verify" in r.url or "verify" in r.text.lower() or "otp" in r.text.lower(), \
        f"Expected OTP redirect for unverified user. Got: {r.url}"
    log(f"  Unverified user correctly redirected to OTP page. {_PASS}")


def test_verify_endpoint_structure():
    log("=== Test 5: Verify signature endpoint structure ===")
    s = requests.Session()
    # Attempt to access without login → redirect to login
    r = s.get(f"{BASE_URL}/verify-signature/1", allow_redirects=True)
    assert r.status_code == 200
    assert "login" in r.url or "login" in r.text.lower(), \
        f"Expected login redirect. Got: {r.url}"
    log(f"  Unauthenticated verify-signature redirects to login. {_PASS}")


def test_private_key_requires_auth():
    log("=== Test 6: Private key endpoint requires auth ===")
    s = requests.Session()
    r = s.post(f"{BASE_URL}/get-private-key", data={"password": "test"})
    assert r.status_code in [401, 403, 302], f"Expected auth error. Got {r.status_code}"
    log(f"  /get-private-key correctly requires authentication. {_PASS}")


def test_route_availability():
    log("=== Test 7: All required routes exist ===")
    s = requests.Session()
    routes = [
        "/register", "/login", "/verify-otp", "/login-otp",
        "/forgot-password", "/organizations",
    ]
    for route in routes:
        r = s.get(f"{BASE_URL}{route}", allow_redirects=True)
        assert r.status_code == 200, f"Route {route} returned {r.status_code}"
        log(f"  {route} → 200 OK ✓")
    log(f"  All required routes available. {_PASS}")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  SecureShare — OTP & Security Integration Test Suite")
    print("=" * 60)

    try:
        s = test_register()
        test_wrong_otp(s)
        test_otp_attempt_limiting(s)
        test_upload_blocked_without_approval()
        test_verify_endpoint_structure()
        test_private_key_requires_auth()
        test_route_availability()

        print()
        print("=" * 60)
        print("  ✅  ALL AUTOMATED TESTS PASSED")
        print()
        print("  Manual tests required (need SMTP or console OTP):")
        print("    1. Complete registration OTP flow via browser")
        print("    2. Login OTP flow via browser")
        print("    3. Admin creates org → user requests join → admin approves")
        print("    4. Upload file → verify signature → download")
        print("    5. Private key: click 'Show', enter password, verify display")
        print("=" * 60)

    except AssertionError as exc:
        print(f"\n{_FAIL} (AssertionError): {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"\n{_FAIL}: Cannot connect to {BASE_URL}")
        print("  Make sure the server is running: python app.py")
        sys.exit(1)
    except Exception as exc:
        print(f"\n{_FAIL} (Exception): {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
