import os
from flask import Blueprint, render_template, redirect, url_for, flash, abort, send_file
from models import Organization, User, File, OrgRequest, AuditLog
from extensions import db
from services import access_control
from services.logging_service import log_event
from utils.helpers import login_required, _require_login
from config import Config
from datetime import datetime

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/create-organization', methods=['GET', 'POST'])
@login_required
def create_organization():
    from flask import request
    user = _require_login()
    if not user or not user.is_admin:
        flash('Admins only.', 'danger')
        return redirect(url_for('file.dashboard'))

    if request.method == 'POST':
        org_name = request.form.get('org_name', '').strip()
        if not org_name:
            flash('Organization name required.', 'warning')
            return redirect(url_for('admin.create_organization'))
        if Organization.query.filter_by(org_name=org_name).first():
            flash('Organization name already taken.', 'warning')
            return redirect(url_for('admin.create_organization'))

        org = Organization(org_name=org_name, created_by=user.id)
        db.session.add(org)
        db.session.flush()
        user.organization_id = org.id
        user.is_approved = True
        db.session.commit()
        log_event(user.id, 'ORG_CREATED', target_id=org.id, details=f'org={org_name}')
        flash(f'Organization "{org_name}" created!', 'success')
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('create_org.html')


@bp.route('/organizations')
@login_required
def list_organizations():
    user = _require_login()
    orgs = Organization.query.order_by(Organization.org_name).all()
    pending_org_ids = {
        r.organization_id for r in
        OrgRequest.query.filter_by(user_id=user.id, status='pending').all()
    }
    return render_template('organizations.html', orgs=orgs, pending_org_ids=pending_org_ids, current_user=user)


@bp.route('/request-join/<int:org_id>', methods=['POST'])
@login_required
def request_join(org_id):
    user = _require_login()
    org = db.session.get(Organization, org_id)
    if not org:
        abort(404)

    existing = OrgRequest.query.filter_by(
        user_id=user.id, organization_id=org_id
    ).filter(OrgRequest.status.in_(['pending', 'approved'])).first()
    if existing:
        flash('You already have an active request or membership.', 'info')
        return redirect(url_for('admin.list_organizations'))

    req = OrgRequest(user_id=user.id, organization_id=org_id, status='pending')
    db.session.add(req)
    db.session.commit()
    log_event(user.id, 'JOIN_REQUEST', target_id=org_id, details=f'org={org.org_name}')
    flash(f'Join request sent to "{org.org_name}". Awaiting approval.', 'info')
    return redirect(url_for('admin.list_organizations'))


@bp.route('/approve-user/<int:request_id>', methods=['POST'])
@login_required
def approve_user(request_id):
    admin = _require_login()
    if not admin or not admin.is_admin:
        abort(403)

    req = db.session.get(OrgRequest, request_id)
    if not req or req.status != 'pending':
        flash('Request not found or already resolved.', 'warning')
        return redirect(url_for('admin.admin_dashboard'))

    if not access_control.can_approve_user(admin, req.organization_id):
        log_event(admin.id, 'APPROVE_DENIED', target_id=req.id, details='Cross-org approval attempt blocked')
        abort(403)

    target_user = db.session.get(User, req.user_id)
    if not target_user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

    req.status = 'approved'
    req.resolved_at = datetime.now()
    target_user.organization_id = req.organization_id
    target_user.is_approved = True
    db.session.commit()

    org = db.session.get(Organization, req.organization_id)
    log_event(admin.id, 'USER_APPROVED', target_id=target_user.id, org_id=admin.organization_id, details=f'org={org.org_name if org else req.organization_id}')
    flash(f'User "{target_user.username}" approved.', 'success')
    return redirect(url_for('admin.admin_dashboard'))


@bp.route('/reject-user/<int:request_id>', methods=['POST'])
@login_required
def reject_user(request_id):
    admin = _require_login()
    if not admin or not admin.is_admin:
        abort(403)

    req = db.session.get(OrgRequest, request_id)
    if not req or req.status != 'pending':
        flash('Request not found or already resolved.', 'warning')
        return redirect(url_for('admin.admin_dashboard'))

    if not access_control.can_approve_user(admin, req.organization_id):
        log_event(admin.id, 'REJECT_DENIED', target_id=req.id, details='Cross-org rejection attempt blocked')
        abort(403)

    target_user = db.session.get(User, req.user_id)
    req.status = 'rejected'
    req.resolved_at = datetime.now()
    db.session.commit()

    log_event(admin.id, 'USER_REJECTED', target_id=(target_user.id if target_user else None), org_id=admin.organization_id, details=f'request_id={request_id}')
    flash('Join request rejected.', 'info')
    return redirect(url_for('admin.admin_dashboard'))


@bp.route('/remove-user/<int:user_id>', methods=['POST'])
@login_required
def remove_user(user_id):
    admin = _require_login()
    if not admin or not admin.is_admin:
        abort(403)

    target = db.session.get(User, user_id)
    if not target:
        abort(404)

    if not access_control.can_approve_user(admin, target.organization_id):
        log_event(admin.id, 'REMOVE_DENIED', target_id=user_id, details='Cross-org removal attempt blocked')
        abort(403)

    target.is_approved = False
    target.organization_id = None
    db.session.commit()
    log_event(admin.id, 'USER_REMOVED', target_id=user_id, org_id=admin.organization_id, details='Removed from org')
    flash(f'User "{target.username}" removed from organization.', 'info')
    return redirect(url_for('admin.admin_dashboard'))


@bp.route('/dashboard')
@bp.route('/')
@login_required
def admin_dashboard():
    user = _require_login()
    if not user or not user.is_admin:
        flash('Admins only.', 'danger')
        return redirect(url_for('auth.login'))

    admin_org_id = user.organization_id
    if admin_org_id:
        users = (User.query.filter(User.organization_id == admin_org_id).order_by(User.username).all())
    else:
        users = [user]

    org_member_ids = {u.id for u in users}
    if org_member_ids:
        files = (File.query.filter(File.sender_id.in_(org_member_ids)).order_by(File.upload_date.desc()).all())
    else:
        files = []

    if admin_org_id:
        pending_reqs = OrgRequest.query.filter_by(organization_id=admin_org_id, status='pending').all()
    else:
        pending_reqs = []

    req_data = []
    for r in pending_reqs:
        req_user = db.session.get(User, r.user_id)
        req_org  = db.session.get(Organization, r.organization_id)
        req_data.append({'req': r, 'user': req_user, 'org': req_org})

    if admin_org_id:
        audit_logs = (AuditLog.query.filter(AuditLog.org_id == admin_org_id).order_by(AuditLog.timestamp.desc()).limit(100).all())
    else:
        audit_logs = []

    all_orgs = Organization.query.all()
    org_map  = {o.id: o.org_name for o in all_orgs}
    user_map = {u.id: u.username for u in users}
    org = db.session.get(Organization, admin_org_id) if admin_org_id else None

    total_users = len(users)
    pending_count = len(req_data)
    total_files = len(files)

    return render_template('admin.html',
                           users=users, files=files,
                           orgs=[org] if org else [],
                           req_data=req_data,
                           audit_logs=audit_logs,
                           user_map=user_map,
                           org_map=org_map,
                           admin_org=org,
                           total_users=total_users,
                           pending_count=pending_count,
                           total_files=total_files)

@bp.route('/open-storage')
@login_required
def open_storage():
    user = _require_login()
    if not user or not user.is_admin:
        abort(403)
    try:
        os.startfile(Config.STORAGE_DIR)
        flash('Opened storage folder.', 'info')
    except Exception as exc:
        flash(f'Could not open folder: {exc}', 'warning')
    return redirect(url_for('admin.admin_dashboard'))

@bp.route('/download-raw/<int:file_id>')
@login_required
def download_raw(file_id):
    user = _require_login()
    if not user or not user.is_admin:
        abort(403)

    file_record = db.session.get(File, file_id)
    if not file_record:
        abort(404)

    file_path = os.path.join(Config.FILES_DIR, file_record.stored_filename)
    if not os.path.exists(file_path):
        flash('Encrypted file not found on disk.', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

    return send_file(
        file_path,
        as_attachment=True,
        download_name=f"{file_record.stored_filename}.enc"
    )

@bp.route('/verify-audit-chain')
@login_required
def verify_audit_chain():
    user = _require_login()
    if not user or not user.is_admin:
        abort(403)
    
    from services.logging_service import verify_log_chain
    is_valid, message = verify_log_chain()
    
    from flask import request, jsonify
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    if best == 'application/json':
        return jsonify({'verified': is_valid, 'message': message})
    
    flash(message, 'success' if is_valid else 'danger')
    return redirect(url_for('admin.admin_dashboard'))
