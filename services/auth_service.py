import bcrypt
from datetime import datetime, timedelta
from flask import current_app
from models import User, Organization, OrgRequest, LoginLog
from extensions import db
from services.logging_service import log_event
from services.crypto_service import CryptoUtils
from otp_utils import create_otp_for_session
from email_utils import send_otp_email
from config import Config

def register_user(username, email, password, reg_type, new_org_name=None, join_org_id=None):
    if User.query.filter_by(username=username).first():
        return False, 'Username already taken.', None
    if User.query.filter_by(email=email).first():
        return False, 'Email address already registered.', None

    org_intent = None
    if reg_type == 'create_org':
        if not new_org_name:
            return False, 'Enter an organization name.', None
        if Organization.query.filter_by(org_name=new_org_name).first():
            return False, f'Organization "{new_org_name}" already exists.', None
        org_intent = {'type': 'create_org', 'org_name': new_org_name}
    elif reg_type == 'join_org':
        if not join_org_id:
            return False, 'Please select an organization.', None
        target_org = db.session.get(Organization, int(join_org_id))
        if not target_org:
            return False, 'Organization not found.', None
        org_intent = {'type': 'join_org', 'org_id': target_org.id, 'org_name': target_org.org_name}

    try:
        private_pem, public_pem = CryptoUtils.generate_key_pair()
        encrypted_priv = CryptoUtils.encrypt_private_key(private_pem, password)
    except Exception as exc:
        return False, 'Key generation failed. Try again.', None

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    otp_data = create_otp_for_session()
    ok, err = send_otp_email(email, otp_data['otp_plain'], purpose='register')
    if not ok:
        return False, f'Registration failed: could not send verification email. {err}', None

    pending_data = {
        'username':       username,
        'email':          email,
        'password_hash':  password_hash,
        'public_key':     public_pem.decode('utf-8'),
        'private_key':    encrypted_priv,
        'reg_type':       reg_type,
        'org_intent':     org_intent,
        'otp_hash':       otp_data['otp_hash'],
        'otp_expiry':     otp_data['otp_expiry'],
        'otp_attempts':   0,
        'otp_last_sent':  otp_data['otp_last_sent'],
    }
    return True, 'A 6-digit OTP has been sent to your email. Please verify to activate your account.', pending_data


def finalize_registration(pending):
    new_user = User(
        username=pending['username'],
        email=pending['email'],
        email_verified=True,
        password_hash=pending['password_hash'],
        public_key=pending['public_key'],
        private_key=pending['private_key'],
        is_approved=True if pending.get('reg_type') == 'standalone' else False,
    )
    db.session.add(new_user)
    db.session.flush()

    org_intent = pending.get('org_intent')
    if org_intent:
        if org_intent['type'] == 'create_org':
            org_name = org_intent['org_name']
            new_org = Organization(org_name=org_name, created_by=new_user.id)
            db.session.add(new_org)
            db.session.flush()
            new_user.organization_id = new_org.id
            new_user.is_approved = True
            new_user.is_admin = True
            new_user.role = 'admin'
            log_event(new_user.id, 'ORG_CREATED', target_id=new_org.id, details=f'org={org_name}')
        elif org_intent['type'] == 'join_org':
            req = OrgRequest(user_id=new_user.id, organization_id=org_intent['org_id'], status='pending')
            db.session.add(req)
    
    db.session.commit()
    log_event(new_user.id, 'ACCOUNT_REGISTERED', details=f"reg_type={pending['reg_type']}")
    return new_user


def authenticate_user(username, password, login_type, org_id_str, remote_addr):
    user = User.query.filter_by(username=username).first()
    if user and user.is_locked():
        log_event(user.id, 'LOGIN_BLOCKED', details='Account locked')
        return False, 'Account temporarily locked. Try again later.', None

    if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        if login_type == 'org':
            if not org_id_str:
                return False, 'Please select an organization to log in as an org member.', None
            try:
                selected_org_id = int(org_id_str)
            except ValueError:
                return False, 'Invalid organization selection.', None
            if user.organization_id != selected_org_id:
                log_event(user.id, 'LOGIN_TYPE_MISMATCH', details=f'Org login but user.org={user.organization_id}, selected={selected_org_id}')
                log = LoginLog(user_id=user.id, ip_address=remote_addr, success=False, note='Org mismatch')
                db.session.add(log)
                db.session.commit()
                return False, 'You are not a member of the selected organization.', None
        else:
            if user.organization_id:
                log_event(user.id, 'LOGIN_TYPE_MISMATCH', details='Individual login but user belongs to an org')
                log = LoginLog(user_id=user.id, ip_address=remote_addr, success=False, note='Should use org login')
                db.session.add(log)
                db.session.commit()
                return False, 'Your account belongs to an organization. Please select "Organization" to log in.', None
        
        user.failed_login_attempts = 0
        db.session.commit()

        log = LoginLog(user_id=user.id, ip_address=remote_addr, success=True)
        db.session.add(log)
        log_event(user.id, 'LOGIN_SUCCESS', details=f'IP={remote_addr}, type={login_type}')
        db.session.commit()

        return True, 'Login successful.', user

    if user:
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            user.account_locked_until = datetime.now() + timedelta(minutes=15)
            log_event(user.id, 'ACCOUNT_LOCKED', details='Too many failed attempts')
            db.session.commit()
            return False, 'Account locked for 15 minutes.', None
        else:
            log = LoginLog(user_id=user.id, ip_address=remote_addr, success=False)
            db.session.add(log)
            db.session.commit()
            return False, 'Invalid username or password.', None
    
    return False, 'Invalid username or password.', None
