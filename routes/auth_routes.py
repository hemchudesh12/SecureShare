from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from extensions import db, limiter
from models import Organization, User
from services import auth_service
from services.crypto_service import CryptoUtils
from services.logging_service import log_event
from utils.helpers import _require_login

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    orgs = Organization.query.order_by(Organization.org_name).all()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        reg_type = request.form.get('reg_type', 'standalone')

        if not username or not password or not email:
            flash('All fields are required.', 'warning')
            return redirect(url_for('auth.register'))

        if '@' not in email or '.' not in email.split('@')[-1]:
            flash('Please enter a valid email address.', 'warning')
            return redirect(url_for('auth.register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('auth.register'))

        new_org_name = request.form.get('new_org_name', '').strip() if reg_type == 'create_org' else None
        join_org_id = request.form.get('join_org_id', '').strip() if reg_type == 'join_org' else None

        success, message, pending_data = auth_service.register_user(
            username=username, email=email, password=password, reg_type=reg_type,
            new_org_name=new_org_name, join_org_id=join_org_id
        )

        if not success:
            flash(message, 'warning' if 'taken' in message or 'exists' in message or 'select' in message or 'found' in message else 'danger')
            return redirect(url_for('auth.register'))

        session['pending_registration'] = pending_data
        flash(message, 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('register.html', orgs=orgs)

@bp.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def verify_otp():
    pending = session.get('pending_registration')
    if not pending:
        flash('Session expired. Please register again.', 'warning')
        return redirect(url_for('auth.register'))

    email = pending['email']

    if request.method == 'POST':
        input_otp = request.form.get('otp', '').strip()

        if not input_otp or not input_otp.isdigit() or len(input_otp) != 6:
            flash('⚠️ Please enter the 6-digit OTP exactly as received.', 'warning')
            return render_template('verify_otp.html', email=email)

        from otp_utils import verify_otp_from_session
        from config import Config
        success, message, new_attempts = verify_otp_from_session(
            pending['otp_hash'],
            pending['otp_expiry'],
            pending['otp_attempts'],
            input_otp,
        )
        pending['otp_attempts'] = new_attempts
        session['pending_registration'] = pending   # write back

        if not success:
            if new_attempts >= Config.MAX_OTP_ATTEMPTS:
                session.pop('pending_registration', None)
                flash(message + ' Please register again.', 'danger')
                return redirect(url_for('auth.register'))
            flash(message, 'danger')
            return render_template('verify_otp.html', email=email)

        # OTP verified — NOW create the user in the database
        auth_service.finalize_registration(pending)
        session.pop('pending_registration', None)
        flash(message + ' You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('verify_otp.html', email=email)

@bp.route('/resend-otp', methods=['POST'])
@limiter.limit("5 per hour")
def resend_otp():
    from otp_utils import can_resend_session, create_otp_for_session
    from email_utils import send_otp_email

    pending = session.get('pending_registration')
    if not pending:
        flash('Session expired. Please register again.', 'warning')
        return redirect(url_for('auth.register'))

    email = pending.get('email')
    if not email:
        flash('No email address on record. Please re-register.', 'danger')
        return redirect(url_for('auth.register'))

    allowed, seconds_left = can_resend_session(pending.get('otp_last_sent'))
    if not allowed:
        flash(f'⏳ Please wait {seconds_left} seconds before requesting a new OTP.', 'warning')
        return redirect(url_for('auth.verify_otp'))

    otp_data = create_otp_for_session()
    ok, err = send_otp_email(email, otp_data['otp_plain'], purpose='register')
    if not ok:
        flash(f'⛔ Failed to send OTP email: {err}', 'danger')
        return redirect(url_for('auth.verify_otp'))

    pending['otp_hash']      = otp_data['otp_hash']
    pending['otp_expiry']    = otp_data['otp_expiry']
    pending['otp_attempts']  = 0
    pending['otp_last_sent'] = otp_data['otp_last_sent']
    session['pending_registration'] = pending

    flash('📧 A new OTP has been sent to your email.', 'info')
    return redirect(url_for('auth.verify_otp'))

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    orgs = Organization.query.order_by(Organization.org_name).all()

    if request.method == 'POST':
        username   = request.form.get('username', '').strip()
        password   = request.form.get('password', '')
        login_type = request.form.get('login_type', 'individual')
        org_id_str = request.form.get('org_id', '').strip()

        success, message, user = auth_service.authenticate_user(username, password, login_type, org_id_str, request.remote_addr)

        if not success:
            flash(message, 'warning' if 'select' in message or 'belongs' in message else 'danger')
            return render_template('login.html', orgs=orgs)

        session.permanent = True
        session['user_id']  = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        session['p_key']    = password

        return redirect(url_for('admin.admin_dashboard' if user.is_admin else 'file.dashboard'))

    return render_template('login.html', orgs=orgs)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    user = _require_login()
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        import bcrypt
        old_pw  = request.form.get('old_password', '')
        new_pw  = request.form.get('new_password', '')

        if not bcrypt.checkpw(old_pw.encode(), user.password_hash.encode()):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        if len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'danger')
            return render_template('change_password.html')

        try:
            old_priv_pem = CryptoUtils.decrypt_private_key(user.private_key, old_pw)
            user.private_key   = CryptoUtils.encrypt_private_key(old_priv_pem, new_pw)
            user.password_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            db.session.commit()
            log_event(user.id, 'PASSWORD_CHANGED')
            session.clear()
            flash('Password changed. Please log in with your new password.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as exc:
            flash(f'Failed to change password: {exc}', 'danger')

    return render_template('change_password.html')

@bp.route('/get-private-key', methods=['POST'])
@limiter.limit("5 per minute")
def get_private_key():
    user = _require_login()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    password = request.form.get('password', '')
    if not password:
        return jsonify({'error': 'Password required'}), 400
    try:
        private_pem = CryptoUtils.decrypt_private_key(user.private_key, password)
        log_event(user.id, 'PRIVATE_KEY_VIEWED', details=f'IP={request.remote_addr}')
        return jsonify({'private_key': private_pem.decode('utf-8')})
    except ValueError:
        log_event(user.id, 'PRIVATE_KEY_FAILED', details='Wrong password')
        return jsonify({'error': 'Incorrect password.'}), 403

@bp.route('/download-private-key', methods=['POST'])
@limiter.limit("3 per hour")
def download_private_key():
    from flask import send_file
    import io
    user = _require_login()
    if not user:
        return redirect(url_for('auth.login'))
    password = request.form.get('password', '')
    try:
        private_pem = CryptoUtils.decrypt_private_key(user.private_key, password)
        log_event(user.id, 'PRIVATE_KEY_DOWNLOADED', details=f'IP={request.remote_addr}')
        return send_file(
            io.BytesIO(private_pem),
            as_attachment=True,
            download_name=f"{user.username}_private_key.pem",
            mimetype='application/x-pem-file'
        )
    except ValueError:
        flash('Incorrect password.', 'danger')
        return redirect(url_for('file.dashboard'))

@bp.route('/download-public-key/<int:user_id>')
def download_public_key(user_id):
    from flask import send_file, abort
    import io
    user = db.session.get(User, user_id)
    if not user or not user.public_key:
        abort(404)
    return send_file(
        io.BytesIO(user.public_key.encode()),
        as_attachment=True,
        download_name=f"{user.username}_public_key.pem",
        mimetype='application/x-pem-file'
    )
