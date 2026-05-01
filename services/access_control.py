from models import User, File, FileShare
from extensions import db
from services.logging_service import log_event

def can_access_file(user: User, file_id: int) -> tuple[bool, str, File | None, FileShare | None]:
    """
    Check if a user can download or view a file.
    Returns (allowed, error_message, file_record, share_record)
    """
    share = FileShare.query.filter_by(file_id=file_id, user_id=user.id).first()
    if not share:
        log_event(user.id, 'ACCESS_DENIED', details=f'Not a recipient. file_id={file_id}')
        return False, "Access denied — you are not a recipient of this file.", None, None

    if share.is_revoked:
        log_event(user.id, 'ACCESS_DENIED', details=f'Access revoked. file_id={file_id}')
        return False, "Access denied — your access has been revoked.", None, None

    from datetime import datetime
    if share.expiry_time and datetime.now() > share.expiry_time:
        log_event(user.id, 'ACCESS_DENIED', details=f'Access expired. file_id={file_id}')
        return False, "Access denied — your access has expired.", None, None

    if share.download_limit and share.download_count >= share.download_limit:
        log_event(user.id, 'ACCESS_DENIED', details=f'Download limit reached. file_id={file_id}')
        return False, "Access denied — download limit reached.", None, None

    file_record = db.session.get(File, file_id)
    if not file_record:
        return False, "File not found.", None, None

    sender = db.session.get(User, file_record.sender_id)
    if (sender and sender.organization_id
            and user.organization_id
            and sender.organization_id != user.organization_id):
        log_event(user.id, 'DOWNLOAD_DENIED', details=f'Cross-org. file_id={file_id}')
        return False, "Cross-organization access denied.", None, None

    return True, "", file_record, share

def can_approve_user(admin: User, target_org_id: int) -> bool:
    # Only approve requests for their own org
    return target_org_id == admin.organization_id
