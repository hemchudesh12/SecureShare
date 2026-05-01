"""
otp_utils.py — Secure OTP generation and verification for SecureShare.

Design:
  - OTP generated with secrets.randbelow() — cryptographically secure.
  - Hashed with SHA-256 before storage — never stored in plaintext.
  - 5-minute expiry enforced on every verification attempt.
  - Maximum 5 attempts; 6th attempt locks verification.
  - 60-second resend cooldown enforced before generating a new OTP.
  - All logging is sanitised — the OTP value is never written to logs.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from config import Config

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Low-level primitives
# ---------------------------------------------------------------------------

def generate_otp() -> str:
    """Return a cryptographically secure, zero-padded 6-digit OTP string."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    """Return the SHA-256 hex-digest of the OTP.  Never store plaintext."""
    return hashlib.sha256(otp.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# Higher-level helpers that operate on a User ORM object
# ---------------------------------------------------------------------------

def set_otp(user, db_session) -> str:
    """
    Generate a fresh OTP, update the user record, and return the plaintext OTP
    so the caller can email it.

    Side-effects on *user*:
      - otp_hash        ← SHA-256(otp)
      - otp_expiry      ← utcnow + OTP_EXPIRY_MINUTES
      - otp_attempts    ← 0
      - otp_last_sent   ← utcnow
    Commits to db_session.
    """
    otp = generate_otp()
    user.otp_hash      = hash_otp(otp)
    user.otp_expiry    = datetime.utcnow() + timedelta(minutes=Config.OTP_EXPIRY_MINUTES)
    user.otp_attempts  = 0
    user.otp_last_sent = datetime.utcnow()
    db_session.commit()

    # Log the event — NOT the OTP value
    _logger.info("OTP issued for user_id=%s (expires in %d min)",
                 user.id, Config.OTP_EXPIRY_MINUTES)
    return otp


def can_resend(user) -> tuple[bool, int]:
    """
    Check whether the 60-second resend cooldown has passed.

    Returns (allowed: bool, seconds_remaining: int).
    """
    if not user.otp_last_sent:
        return True, 0
    elapsed = (datetime.utcnow() - user.otp_last_sent).total_seconds()
    if elapsed < 60:
        remaining = int(60 - elapsed)
        return False, remaining
    return True, 0


def verify_otp(user, input_otp: str, db_session) -> tuple[bool, str]:
    """
    Verify the supplied OTP against the stored hash.

    Returns (success: bool, message: str).

    Security behaviour:
      * Attempt counter is incremented BEFORE we compare — prevents timing games.
      * After MAX_OTP_ATTEMPTS failures the account OTP is locked (otp_hash cleared).
      * Expired OTPs always fail, even if the hash matches.
      * On success, OTP fields are cleared.
    """
    # ── Pre-condition checks ─────────────────────────────────────────────
    if not user.otp_hash:
        return False, "No OTP is pending. Please request a new one."

    # Increment attempts first (before comparison) to prevent bypass
    user.otp_attempts = (user.otp_attempts or 0) + 1
    db_session.commit()

    # ── Lockout check ────────────────────────────────────────────────────
    if user.otp_attempts > Config.MAX_OTP_ATTEMPTS:
        user.otp_hash   = None
        user.otp_expiry = None
        db_session.commit()
        _logger.warning("OTP locked for user_id=%s after %d attempts",
                        user.id, user.otp_attempts - 1)
        return False, (
            f"⛔ Too many failed attempts ({Config.MAX_OTP_ATTEMPTS} max). "
            "Verification locked — please register again or contact support."
        )

    # ── Expiry check ─────────────────────────────────────────────────────
    if not user.otp_expiry or datetime.utcnow() > user.otp_expiry:
        _logger.info("Expired OTP attempt for user_id=%s", user.id)
        return False, "⏰ OTP has expired. Please request a new one."

    # ── Hash comparison (timing-safe) ────────────────────────────────────
    expected = user.otp_hash
    provided = hash_otp(input_otp.strip())

    if not secrets.compare_digest(expected, provided):
        remaining = Config.MAX_OTP_ATTEMPTS - user.otp_attempts
        _logger.info("Invalid OTP attempt for user_id=%s (%d remaining)",
                     user.id, remaining)
        if remaining <= 0:
            user.otp_hash   = None
            user.otp_expiry = None
            db_session.commit()
            return False, (
                f"⛔ Too many failed attempts. Verification locked — "
                "please register again or contact support."
            )
        return False, f"❌ Invalid OTP. {remaining} attempt(s) remaining."

    # ── Success ──────────────────────────────────────────────────────────
    user.email_verified = True
    user.otp_hash       = None
    user.otp_expiry     = None
    user.otp_attempts   = 0
    db_session.commit()
    _logger.info("Email verified successfully for user_id=%s", user.id)
    return True, "✅ Email verified successfully!"


# ---------------------------------------------------------------------------
# Session-based OTP helpers (no DB user required)
# ---------------------------------------------------------------------------

def create_otp_for_session() -> dict:
    """Generate OTP data suitable for storing in a Flask session.

    Returns a dict with:
        otp_plain  — the 6-digit code to email (use immediately, don't store)
        otp_hash   — SHA-256 hex digest (safe to store in session)
        otp_expiry — ISO-format expiry timestamp string
        otp_attempts — 0
        otp_last_sent — ISO-format timestamp string
    """
    otp = generate_otp()
    return {
        "otp_plain":     otp,
        "otp_hash":      hash_otp(otp),
        "otp_expiry":    (datetime.utcnow()
                          + timedelta(minutes=Config.OTP_EXPIRY_MINUTES)
                         ).isoformat(),
        "otp_attempts":  0,
        "otp_last_sent": datetime.utcnow().isoformat(),
    }


def verify_otp_from_session(
    stored_hash: str,
    expiry_iso: str,
    attempts: int,
    input_otp: str,
) -> tuple[bool, str, int]:
    """Verify an OTP using values stored in the Flask session.

    Returns (success, message, updated_attempts).
    The caller must write *updated_attempts* back into the session.
    """
    attempts += 1  # increment before comparison

    if attempts > Config.MAX_OTP_ATTEMPTS:
        _logger.warning("Session OTP locked after %d attempts", attempts - 1)
        return False, (
            f"⛔ Too many failed attempts ({Config.MAX_OTP_ATTEMPTS} max). "
            "Please register again."
        ), attempts

    expiry = datetime.fromisoformat(expiry_iso)
    if datetime.utcnow() > expiry:
        return False, "⏰ OTP has expired. Please request a new one.", attempts

    if not secrets.compare_digest(stored_hash, hash_otp(input_otp.strip())):
        remaining = Config.MAX_OTP_ATTEMPTS - attempts
        if remaining <= 0:
            return False, (
                "⛔ Too many failed attempts. Please register again."
            ), attempts
        return False, f"❌ Invalid OTP. {remaining} attempt(s) remaining.", attempts

    return True, "✅ Email verified successfully!", attempts


def can_resend_session(last_sent_iso: str | None) -> tuple[bool, int]:
    """Check 60-second resend cooldown using an ISO timestamp from the session."""
    if not last_sent_iso:
        return True, 0
    elapsed = (datetime.utcnow() - datetime.fromisoformat(last_sent_iso)).total_seconds()
    if elapsed < 60:
        return False, int(60 - elapsed)
    return True, 0
