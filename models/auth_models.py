from datetime import datetime
from extensions import db

class Organization(db.Model):
    __tablename__ = 'organizations'
    __bind_key__  = 'auth_db'

    id         = db.Column(db.Integer, primary_key=True)
    org_name   = db.Column(db.String(100), unique=True, nullable=False)
    created_by = db.Column(db.Integer, nullable=False)  # admin user ID
    created_at = db.Column(db.DateTime, default=datetime.now)

class User(db.Model):
    __tablename__ = 'users'
    __bind_key__  = 'auth_db'

    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash  = db.Column(db.String(200), nullable=False)

    # RSA Key pair
    public_key     = db.Column(db.Text,    nullable=True)   # PEM public key
    private_key    = db.Column(db.Text,    nullable=True)   # AES-encrypted PEM

    # Account state
    is_approved    = db.Column(db.Boolean, default=False,   nullable=False)
    is_admin       = db.Column(db.Boolean, default=False,   nullable=False)
    role           = db.Column(db.String(20), default='member', nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.now)

    # Organization
    organization_id = db.Column(db.Integer, nullable=True)

    # Email + OTP verification
    email           = db.Column(db.String(200), unique=True, nullable=True)
    email_verified  = db.Column(db.Boolean, default=False, nullable=False)
    otp_hash        = db.Column(db.String(64),  nullable=True)   # SHA-256 hex — never plaintext
    otp_expiry      = db.Column(db.DateTime,    nullable=True)
    otp_attempts    = db.Column(db.Integer, default=0, nullable=False)
    otp_last_sent   = db.Column(db.DateTime,    nullable=True)

    # Account lockout
    failed_login_attempts = db.Column(db.Integer,  default=0,  nullable=False)
    account_locked_until  = db.Column(db.DateTime, nullable=True)

    def is_locked(self) -> bool:
        """Return True if the account is currently locked."""
        if self.account_locked_until and self.account_locked_until > datetime.now():
            return True
        return False

class OrgRequest(db.Model):
    __tablename__ = 'organization_requests'
    __bind_key__  = 'auth_db'

    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, nullable=False)
    organization_id = db.Column(db.Integer, nullable=False)
    status          = db.Column(db.String(20), default='pending', nullable=False)
    requested_at    = db.Column(db.DateTime, default=datetime.now)
    resolved_at     = db.Column(db.DateTime, nullable=True)

class AuditLog(db.Model):
    """Immutable append-only audit trail for all sensitive actions."""
    __tablename__ = 'audit_logs'
    __bind_key__  = 'auth_db'

    id        = db.Column(db.Integer, primary_key=True)
    actor_id  = db.Column(db.Integer, nullable=True)   # None = system
    org_id    = db.Column(db.Integer, nullable=True)   # Organization this entry belongs to
    action    = db.Column(db.String(80), nullable=False)
    target_id = db.Column(db.Integer,   nullable=True)
    details   = db.Column(db.Text,      nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    prev_hash = db.Column(db.String(64), nullable=True)
    current_hash = db.Column(db.String(64), nullable=True)

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    __bind_key__  = 'auth_db'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(45))
    success    = db.Column(db.Boolean, default=True)
    note       = db.Column(db.String(200), nullable=True)

class PasswordReset(db.Model):
    __tablename__ = 'password_resets'
    __bind_key__  = 'auth_db'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, nullable=False)
    reset_token = db.Column(db.String(100), unique=True, nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    used        = db.Column(db.Boolean, default=False)
