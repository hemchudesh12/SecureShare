import os
import uuid
import json
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, session, jsonify, abort, send_file, Response, current_app, stream_with_context
)
from werkzeug.utils import secure_filename
from models import Organization, User, File, FileShare, OrgRequest, VerificationLog
from extensions import db
from services import file_service, access_control, sse_bus
from services.crypto_service import CryptoUtils
from services.logging_service import log_event
from utils.helpers import login_required, verified_required, _require_login, _org_members, _safe_remove, _wants_json
from config import Config
from tasks import async_upload

bp = Blueprint('file', __name__)

@bp.route('/')
def index():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin.admin_dashboard'))
        return redirect(url_for('file.dashboard'))
    return redirect(url_for('auth.login'))

@bp.route('/dashboard')
@login_required
def dashboard():
    user = _require_login()
    org = db.session.get(Organization, user.organization_id) if user.organization_id else None

    pending_request = OrgRequest.query.filter_by(user_id=user.id, status='pending').first()

    files_uploaded_count = File.query.filter_by(sender_id=user.id).count()
    files_received_count = (db.session.query(FileShare)
                            .join(File, FileShare.file_id == File.id)
                            .filter(FileShare.user_id == user.id, File.sender_id != user.id)
                            .count())
    
    org_members = _org_members(user)
    members_count = len(org_members) + 1 if user.organization_id else 1
    
    pending_requests = []
    if user.is_admin and user.organization_id:
        pending_reqs_raw = OrgRequest.query.filter_by(organization_id=user.organization_id, status='pending').all()
        for r in pending_reqs_raw:
            req_user = db.session.get(User, r.user_id)
            req_org = db.session.get(Organization, r.organization_id)
            pending_requests.append({'req': r, 'user': req_user, 'org': req_org})

    return render_template(
        'dashboard.html',
        current_user=user,
        org=org,
        pending_request=pending_request,
        files_uploaded_count=files_uploaded_count,
        files_received_count=files_received_count,
        members_count=members_count,
        pending_requests=pending_requests,
    )

@bp.route('/upload-page')
@login_required
def upload_page():
    user = _require_login()
    org = db.session.get(Organization, user.organization_id) if user.organization_id else None
    org_members = [m for m in _org_members(user) if m.id != user.id]
    return render_template('upload.html', current_user=user, org=org, org_members=org_members)

@bp.route('/my-files')
@login_required
def my_files():
    user = _require_login()
    org = db.session.get(Organization, user.organization_id) if user.organization_id else None
    
    my_files_raw = File.query.filter_by(sender_id=user.id).order_by(File.upload_date.desc()).all()
    files_data = []
    for f in my_files_raw:
        shares = FileShare.query.filter(FileShare.file_id == f.id, FileShare.user_id != user.id).all()
        recipients_info = []
        for s in shares:
            r_user = db.session.get(User, s.user_id)
            if r_user:
                recipients_info.append({'share': s, 'user': r_user})
        files_data.append((f, recipients_info, len(recipients_info)))
        
    return render_template('my_files.html', current_user=user, org=org, files=files_data)

@bp.route('/shared-with-me')
@login_required
def shared_with_me():
    user = _require_login()
    org = db.session.get(Organization, user.organization_id) if user.organization_id else None
    
    raw_files = (
        db.session.query(File, FileShare)
        .join(FileShare, File.id == FileShare.file_id)
        .filter(FileShare.user_id == user.id, File.sender_id != user.id)
        .order_by(File.upload_date.desc())
        .all()
    )
    sender_ids = {f.sender_id for f, _ in raw_files if f.sender_id}
    sender_map = {u.id: u for u in User.query.filter(User.id.in_(sender_ids)).all()} if sender_ids else {}
    
    shared_files = [(f, fs, sender_map.get(f.sender_id)) for f, fs in raw_files]
    
    file_ids = [f.id for f, _, _ in shared_files]
    vlogs = VerificationLog.query.filter(
        VerificationLog.verified_by == user.id,
        VerificationLog.file_id.in_(file_ids)
    ).all() if file_ids else []
    
    vlog_map = {}
    for vl in vlogs:
        if vl.file_id not in vlog_map or vlog_map[vl.file_id].verification_time < vl.verification_time:
            vlog_map[vl.file_id] = vl
            
    return render_template('shared_with_me.html', current_user=user, org=org, files=shared_files, vlog_map=vlog_map)

@bp.route('/security')
@login_required
def security_page():
    user = _require_login()
    org = db.session.get(Organization, user.organization_id) if user.organization_id else None
    return render_template('security.html', current_user=user, org=org)

@bp.route('/upload', methods=['POST'])
@login_required
@verified_required
def upload_file():
    """Accept a multipart upload, save the file to a temp path, and queue an
    async Celery task.  Returns 202 JSON with the task_id immediately so the
    browser can begin polling /upload-status/<task_id>.
    """
    user = _require_login()
    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected.', 'warning')
        return redirect(url_for('file.upload_page'))

    # Save the uploaded bytes to a temp path right now so the HTTP request
    # can close before the encryption work begins.
    temp_filename = f"tmp_{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    temp_path     = os.path.join(current_app.config['STORAGE_DIR'], temp_filename)
    file.save(temp_path)

    recipient_ids  = request.form.getlist('recipients')
    expiry_iso     = request.form.get('expiry_time', '')
    limit_str      = request.form.get('download_limit', None)
    session_pw     = session.get('p_key')   # matches how the sync route accesses the password

    task = async_upload.delay(
        temp_path         = temp_path,
        original_filename = file.filename,
        owner_id          = user.id,
        sender_id         = user.id,
        recipient_ids     = recipient_ids,
        session_password  = session_pw,
        expiry_iso        = expiry_iso,
        download_limit    = int(limit_str) if limit_str and str(limit_str).isdigit() else None,
    )
    return jsonify({'task_id': task.id}), 202


@bp.route('/upload-status/<task_id>')
@login_required
def upload_status(task_id):
    """Poll endpoint for async upload progress.

    Returns JSON with keys: state, percent, msg, redirect.
    """
    task = async_upload.AsyncResult(task_id)

    if task.state == 'PENDING':
        return jsonify({'state': 'PENDING', 'percent': 0, 'msg': 'Queued'})

    elif task.state == 'PROGRESS':
        return jsonify({
            'state':   'PROGRESS',
            'percent': task.info.get('percent', 0),
            'msg':     task.info.get('msg', ''),
        })

    elif task.state == 'SUCCESS':
        return jsonify({
            'state':    'SUCCESS',
            'redirect': task.result.get('redirect', '/my-files'),
        })

    else:  # FAILURE or REVOKED
        return jsonify({
            'state': 'FAILURE',
            'msg':   'Upload failed. Please try again.',
        }), 500


@bp.route('/download/<int:file_id>')
@verified_required
def download_file(file_id):
    user = _require_login()
    allowed, err_msg, file_record, share_record = access_control.can_access_file(user, file_id)
    if not allowed:
        flash(err_msg, 'danger')
        return redirect(url_for('file.dashboard'))

    success, result = file_service.process_download(user, file_record, share_record, session['p_key'], request.remote_addr)
    if not success:
        flash(f'❌ {result}', 'danger')
        return redirect(url_for('file.dashboard'))

    # result is a generator — no plaintext file on disk, no cleanup needed.
    # Signature was verified inside process_download before this generator was created.
    return Response(
        result,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{file_record.filename}"'
        }
    )

@bp.route('/verify/<int:file_id>')
@bp.route('/verify-signature/<int:file_id>')
@login_required
def verify_signature_standalone(file_id):
    user = _require_login()
    allowed, err_msg, file_record, share_record = access_control.can_access_file(user, file_id)
    if not allowed:
        flash(err_msg, 'danger')
        return redirect(url_for('file.dashboard'))
    
    sender = db.session.get(User, file_record.sender_id)

    result = {
        'file_id':         file_id,
        'filename':        file_record.filename,
        'sender':          sender.username if sender else 'Unknown',
        'sender_public_key': sender.public_key if sender else None,
        'timestamp':       (file_record.upload_date.isoformat() if file_record.upload_date else None),
        'verified':        False,
        'integrity_flag':  False,
        'message':         '',
        'recomputed_hash': 'N/A',
    }

    enc_path = os.path.join(Config.FILES_DIR, file_record.stored_filename)

    try:
        private_key_pem = CryptoUtils.decrypt_private_key(user.private_key, session['p_key'])
        aes_key = CryptoUtils.decrypt_aes_key(share_record.encrypted_aes_key, private_key_pem)

        # Hash-only pass — no plaintext written to disk
        recomputed_hash = CryptoUtils.compute_plaintext_hash_stream(enc_path, aes_key, file_record.iv)

        result['recomputed_hash'] = recomputed_hash.hex()

        if not sender or not sender.public_key:
            raise ValueError("Sender public key unavailable.")

        is_valid = CryptoUtils.verify_hash_signature(recomputed_hash, file_record.digital_signature, sender.public_key)

        result['verified']      = is_valid
        result['integrity_flag'] = is_valid
        result['message'] = (
            '✅ Digital Signature Verified — File is Authentic'
            if is_valid else
            '❌ Signature INVALID — File Has Been Tampered'
        )

        v_log = VerificationLog(
            file_id=file_id,
            verified_by=user.id,
            verification_status='VALID' if is_valid else 'INVALID',
            ip_address=request.remote_addr,
        )
        db.session.add(v_log)
        db.session.commit()

        if not is_valid:
            log_event(user.id, 'SIGNATURE_INVALID', target_id=file_id, details='Standalone verify — tamper detected')

    except Exception as exc:
        result['message'] = f'Error during verification: {exc}'

    if _wants_json():
        return jsonify(result)
    return render_template('verify.html', result=result)

@bp.route('/revoke-access', methods=['POST'])
@login_required
def revoke_access():
    user = _require_login()
    file_id_str = request.form.get('file_id')
    recipient_id_str = request.form.get('recipient_id')
    
    if not file_id_str or not recipient_id_str:
        flash('Missing parameters.', 'danger')
        return redirect(url_for('file.my_files'))
        
    try:
        file_id = int(file_id_str)
        recipient_id = int(recipient_id_str)
        success, msg = file_service.revoke_access(file_id, recipient_id, user)
        flash(msg, 'success' if success else 'danger')
    except ValueError:
        flash('Invalid parameters.', 'danger')
        
    return redirect(url_for('file.my_files'))

@bp.route('/sse/download-counts')
@login_required
def sse_download_counts():
    """Server-Sent Events stream: pushes a JSON event to the file owner
    the instant any recipient downloads one of their files.

    The browser connects once via EventSource; no polling needed.
    Each event has the form:
        data: {"share_id": 42, "download_count": 3, "download_limit": 10, "is_revoked": false}
    """
    user = _require_login()
    owner_id = user.id
    q = sse_bus.subscribe(owner_id)

    @stream_with_context
    def event_stream():
        import queue as _queue
        try:
            # Send a keep-alive comment every 25 s to prevent proxy timeouts
            import time
            last_ping = time.time()
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {json.dumps(payload)}\n\n"
                except _queue.Empty:
                    # keep-alive
                    yield ": ping\n\n"
                    last_ping = time.time()
        except GeneratorExit:
            pass
        finally:
            sse_bus.unsubscribe(owner_id, q)

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':  'no-cache',
            'X-Accel-Buffering': 'no',   # disable Nginx buffering
        }
    )


@bp.route('/download-counts')
@login_required
def download_counts():
    """Return real-time download count data for all shares belonging to the
    current user's uploaded files.

    Response JSON: { "<share_id>": { "download_count": int, "download_limit": int|null, "is_revoked": bool } }
    """
    user = _require_login()
    my_file_ids = [f.id for f in File.query.filter_by(sender_id=user.id).all()]
    if not my_file_ids:
        return jsonify({})

    shares = FileShare.query.filter(
        FileShare.file_id.in_(my_file_ids),
        FileShare.user_id != user.id
    ).all()

    data = {}
    for s in shares:
        data[str(s.id)] = {
            'download_count': s.download_count,
            'download_limit': s.download_limit,
            'is_revoked': s.is_revoked,
        }
    return jsonify(data)


@bp.route('/file-access-history/<int:file_id>')
@login_required
def file_access_history(file_id):
    user = _require_login()
    file_record = db.session.get(File, file_id)
    if not file_record:
        abort(404)
        
    if file_record.sender_id != user.id and not user.is_admin:
        abort(403)
        
    history = file_service.get_access_history(file_id)
    
    data = []
    for log in history:
        actor = db.session.get(User, log.user_id)
        data.append({
            'user': actor.username if actor else f'User {log.user_id}',
            'time': log.access_time.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': log.ip_address or 'Unknown',
            'status': log.verification_status
        })
        
    return jsonify({'history': data})
