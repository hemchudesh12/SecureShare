"""
email_utils.py — Production-ready SMTP email delivery for SecureShare.

Security guarantees:
  - OTP is NEVER printed to console, never written to log files, never
    returned in any API response.
  - Credentials are read from environment variables only.
  - STARTTLS enforced on every connection.
  - Each send function returns (success: bool, error: str | None) so the
    caller can roll back registration if delivery fails.

Gmail setup:
  1. Enable 2-Step Verification on the sender Google account.
  2. Go to Google Account → Security → App Passwords.
  3. Generate an App Password for "Mail" / "Other".
  4. Set environment variables:
       Windows : set MAIL_USERNAME=you@gmail.com
                 set MAIL_PASSWORD=xxxx xxxx xxxx xxxx
       Linux   : export MAIL_USERNAME=you@gmail.com
                 export MAIL_PASSWORD=xxxxxxxxxxxx
"""

import ssl
import smtplib
import logging
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import Config

# Dedicated logger — propagation disabled so nothing leaks to file handlers.
_log = logging.getLogger("secureshare.mail")
_log.propagate = False
_log.addHandler(logging.StreamHandler())   # stderr only, no OTP ever logged


# ---------------------------------------------------------------------------
# Internal: build the OTP email
# ---------------------------------------------------------------------------

def _build_otp_email(to_email: str, otp_code: str, purpose: str) -> MIMEMultipart:
    """Build a styled HTML + plain-text OTP email.

    NOTE: otp_code is embedded in email body only — it is NEVER logged here.
    """
    subject = "SecureShare \u2013 Email Verification Code"

    plain = (
        f"Your SecureShare verification code is:\n\n"
        f"    {otp_code}\n\n"
        f"This code is valid for {Config.OTP_EXPIRY_MINUTES} minutes.\n"
        "Do not share this code with anyone.\n\n"
        "If you did not register, ignore this email.\n\n"
        "\u2014 SecureShare Security Team"
    )

    html = f"""\
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f6f9;padding:30px;margin:0;">
<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:10px;
            padding:32px;box-shadow:0 4px 16px rgba(0,0,0,.10);">

  <h2 style="color:#2c3e50;margin:0 0 4px;">&#128274; SecureShare</h2>
  <p style="color:#7f8c8d;margin:0 0 24px;font-size:14px;">
    {"Email Verification" if purpose == "register" else "Verification"}
  </p>

  <hr style="border:none;border-top:1px solid #ecf0f1;margin-bottom:24px;">

  <p style="color:#2c3e50;">Your verification code is:</p>

  <div style="text-align:center;margin:24px 0;">
    <span style="font-size:40px;font-weight:bold;letter-spacing:12px;
                 color:#2980b9;background:#eaf4fd;padding:14px 28px;
                 border-radius:8px;font-family:monospace;">{otp_code}</span>
  </div>

  <p style="color:#7f8c8d;font-size:13px;margin-bottom:8px;">
    &#9201; This code expires in
    <strong>{Config.OTP_EXPIRY_MINUTES} minutes</strong>.
  </p>

  <div style="background:#fef9e7;border-left:4px solid #f1c40f;
              padding:12px 16px;border-radius:4px;margin:20px 0;">
    <p style="margin:0;color:#7d6608;font-size:13px;">
      &#9888;&#65039; <strong>Security Warning:</strong> Never share this code.
      SecureShare staff will <em>never</em> ask for it.
      If you did not register, you can safely ignore this email.
    </p>
  </div>

  <p style="color:#bdc3c7;font-size:11px;text-align:center;margin-top:24px;">
    SecureShare &mdash; End-to-End Encrypted File Sharing
  </p>
</div>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = Config.MAIL_FROM or Config.MAIL_USERNAME
    msg["To"]      = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))
    return msg


# ---------------------------------------------------------------------------
# Internal: SMTP delivery
# ---------------------------------------------------------------------------

def _send_via_smtp(to_email: str, msg: MIMEMultipart) -> tuple[bool, str | None]:
    """
    Open a STARTTLS SMTP connection to Gmail and deliver *msg*.

    Returns (True, None) on success, (False, error_description) on failure.
    The OTP is embedded in *msg* and is NEVER extracted or logged here.
    """
    if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
        return False, (
            "SMTP not configured. "
            "Set MAIL_USERNAME and MAIL_PASSWORD environment variables."
        )

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(msg["From"], [to_email], msg.as_string())

        _log.info("OTP email delivered to %s", to_email)
        return True, None

    except smtplib.SMTPAuthenticationError as exc:
        _log.error("SMTP authentication failed: %s", type(exc).__name__)
        return False, (
            "Email authentication failed. "
            "Check your MAIL_USERNAME and MAIL_PASSWORD (App Password) settings."
        )
    except smtplib.SMTPRecipientsRefused:
        _log.error("Recipient refused for %s", to_email)
        return False, "The email address was rejected by the mail server."
    except smtplib.SMTPException as exc:
        _log.error("SMTP error sending to %s: %s", to_email, type(exc).__name__)
        return False, "An SMTP error occurred while sending the verification email."
    except TimeoutError:
        _log.error("SMTP connection timed out sending to %s", to_email)
        return False, "Connection to the mail server timed out. Please try again."
    except OSError as exc:
        # Covers ConnectionRefusedError, ConnectionResetError, gaierror, etc.
        _log.error("Network error sending to %s: %s", to_email, type(exc).__name__)
        return False, "Could not connect to the mail server. Check your network."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_otp_email(
    to_email: str,
    otp_code: str,
    purpose:  str = "register",
) -> tuple[bool, str | None]:
    """
    Send an OTP verification email **synchronously** and return the result.

    Returns:
        (True,  None)          — email delivered successfully
        (False, error_string)  — delivery failed; caller should surface the error

    The OTP is embedded in the email MIME body only.
    It is NEVER printed, logged, or returned to any caller.

    Why synchronous?  In production the registration endpoint must know
    whether the email was delivered before committing the user record.
    A background thread would hide failures from the request cycle.
    """
    msg = _build_otp_email(to_email, otp_code, purpose)
    return _send_via_smtp(to_email, msg)


# ---------------------------------------------------------------------------
# Join-request / approval notification emails (fire-and-forget, no OTP)
# ---------------------------------------------------------------------------

def _build_join_request_email(
    admin_email: str, requester: str, org_name: str
) -> MIMEMultipart:
    subject = f'\U0001f3e2 SecureShare \u2014 New Join Request for "{org_name}"'
    plain = (
        f"User '{requester}' has requested to join '{org_name}'.\n"
        "Log in to the admin dashboard to approve or reject the request.\n"
    )
    html = f"""\
<html><body style="font-family:Arial,sans-serif;background:#f4f6f9;padding:30px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:10px;
            padding:30px;box-shadow:0 4px 12px rgba(0,0,0,.1);">
  <h2 style="color:#2c3e50;">\U0001f3e2 SecureShare</h2>
  <p style="color:#7f8c8d;">Organization Join Request</p>
  <hr style="border:none;border-top:1px solid #ecf0f1;">
  <p style="color:#2c3e50;">
    User <strong>{requester}</strong> has requested to join
    <strong>{org_name}</strong>.
  </p>
  <p style="color:#7f8c8d;font-size:13px;">
    Log in to the Admin Dashboard to approve or reject this request.
  </p>
  <p style="color:#bdc3c7;font-size:11px;text-align:center;margin-top:24px;">
    SecureShare \u2014 End-to-End Encrypted File Sharing
  </p>
</div>
</body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = Config.MAIL_FROM or Config.MAIL_USERNAME or "noreply@secureshare.app"
    msg["To"]      = admin_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))
    return msg


def _build_approval_email(
    user_email: str, org_name: str, approved: bool
) -> MIMEMultipart:
    if approved:
        subject   = f'\u2705 SecureShare \u2014 Approved for "{org_name}"'
        body_text = f"Your request to join '{org_name}' has been approved."
        body_html = (
            f"<p style='color:#27ae60;'>\u2705 Your request to join "
            f"<strong>{org_name}</strong> has been <strong>approved</strong>!</p>"
        )
    else:
        subject   = f'\u274c SecureShare \u2014 Join request for "{org_name}" rejected'
        body_text = f"Your request to join '{org_name}' has been rejected."
        body_html = (
            f"<p style='color:#e74c3c;'>\u274c Your request to join "
            f"<strong>{org_name}</strong> was <strong>rejected</strong>.</p>"
        )

    html = f"""\
<html><body style="font-family:Arial,sans-serif;background:#f4f6f9;padding:30px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:10px;
            padding:30px;box-shadow:0 4px 12px rgba(0,0,0,.1);">
  <h2 style="color:#2c3e50;">\U0001f3e2 SecureShare \u2014 Organization Update</h2>
  <hr style="border:none;border-top:1px solid #ecf0f1;">
  {body_html}
  <p style="color:#bdc3c7;font-size:11px;text-align:center;margin-top:24px;">
    SecureShare \u2014 End-to-End Encrypted File Sharing
  </p>
</div>
</body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = Config.MAIL_FROM or Config.MAIL_USERNAME or "noreply@secureshare.app"
    msg["To"]      = user_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(html,      "html"))
    return msg


def _fire_and_forget(target, *args) -> None:
    """Send a non-critical notification email in a background daemon thread."""
    threading.Thread(target=target, args=args, daemon=True).start()


def send_join_request_email(
    admin_email: str, requester: str, org_name: str
) -> None:
    """Notify an org admin of a pending join request (best-effort, non-blocking)."""
    msg = _build_join_request_email(admin_email, requester, org_name)
    _fire_and_forget(_send_via_smtp, admin_email, msg)


def send_approval_notification_email(
    user_email: str, org_name: str, approved: bool
) -> None:
    """Notify a user of their join-request outcome (best-effort, non-blocking)."""
    msg = _build_approval_email(user_email, org_name, approved)
    _fire_and_forget(_send_via_smtp, user_email, msg)
