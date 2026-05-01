import os
from functools import wraps
from flask import session, redirect, url_for, flash, request
from models import User
from extensions import db

def _require_login() -> User | None:
    """Return the logged-in User, or None."""
    uid = session.get('user_id')
    if not uid:
        return None
    return db.session.get(User, uid)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _require_login()
        if not user:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _require_login()
        if not user or not user.is_admin:
            flash('Admins only.', 'danger')
            return redirect(url_for('file.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _require_login()
        if not user:
            return redirect(url_for('auth.login'))
        if not user.email_verified:
            from services.logging_service import log_event
            flash('⛔ You must verify your email.', 'warning')
            log_event(user.id, 'ACTION_BLOCKED', details='Email not verified')
            return redirect(url_for('file.dashboard'))
        if not user.is_approved:
            from services.logging_service import log_event
            flash('⛔ Organization approval required.', 'warning')
            log_event(user.id, 'ACTION_BLOCKED', details='Not approved')
            return redirect(url_for('file.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def _org_members(user: User) -> list[User]:
    if not user.organization_id:
        return []
    return User.query.filter(
        User.id != user.id,
        User.organization_id == user.organization_id,
        User.is_approved == True
    ).order_by(User.username).all()

def _wants_json() -> bool:
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json'

def _safe_remove(path: str | None) -> None:
    if path:
        try:
            os.remove(path)
        except OSError:
            pass
