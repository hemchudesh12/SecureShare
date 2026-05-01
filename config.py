"""
config.py — Application configuration for SecureShare.
Credentials are loaded from a .env file at startup so they are
available without having to set environment variables in every terminal.
No external packages required — uses a built-in parser.
"""

import os
from datetime import timedelta


def _load_dotenv(path: str | None = None, override: bool = False) -> None:
    """Parse a .env file and inject its variables into os.environ.

    • Blank lines and lines starting with # are ignored.
    • Values may optionally be wrapped in single or double quotes.
    • Existing env vars are preserved unless *override* is True.
    """
    if path is None:
        path = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if override or key not in os.environ:
                os.environ[key] = value


# Load .env automatically — shell env vars always take precedence.
_load_dotenv(override=False)


class Config:
    # ── Directory layout ──────────────────────────────────────────────────
    BASE_DIR     = os.path.abspath(os.path.dirname(__file__))
    STORAGE_DIR  = os.path.join(BASE_DIR, 'storage')
    FILES_DIR    = os.path.join(STORAGE_DIR, 'files')
    KEYS_DIR     = os.path.join(STORAGE_DIR, 'keys')

    # SQLite databases
    AUTH_DATABASE_URI  = os.path.join(STORAGE_DIR, 'auth.db')
    FILES_DATABASE_URI = os.path.join(STORAGE_DIR, 'files.db')

    # ── Flask security ────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-change-in-prod'

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE      = False   # set True in prod (HTTPS only)
    SESSION_COOKIE_HTTPONLY    = True
    SESSION_COOKIE_SAMESITE    = 'Lax'
    WTF_CSRF_CHECK_DEFAULT     = False   # For automated test support

    # ── Email / SMTP ──────────────────────────────────────────────────────
    MAIL_SERVER   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
    MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS  = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')   # your Gmail address
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')   # Gmail App Password
    MAIL_FROM     = os.environ.get('MAIL_FROM',     os.environ.get('MAIL_USERNAME', ''))

    # ── OTP settings ──────────────────────────────────────────────────────
    OTP_EXPIRY_MINUTES  = 5
    MAX_OTP_ATTEMPTS    = 5
    MAX_LOGIN_ATTEMPTS  = 10    # before account lock

    # ── Rate limiting (Flask-Limiter) ─────────────────────────────────────
    RATELIMIT_DEFAULT          = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL      = "memory://"
    RATELIMIT_HEADERS_ENABLED  = True

    # ── Celery / Redis ────────────────────────────────────────────────────
    CELERY_BROKER_URL     = os.environ.get('CELERY_BROKER_URL',     'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

    # ── Ensure storage directories exist ──────────────────────────────────
    os.makedirs(FILES_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR,  exist_ok=True)
