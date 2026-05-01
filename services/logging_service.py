import logging
from models import AuditLog, User
from extensions import db

logger = logging.getLogger(__name__)

import hashlib
from datetime import datetime

def log_event(actor_id, action: str, target_id: int | None = None, details: str | None = None, org_id: int | None = None):
    """Write an immutable audit log entry tagged to an organization."""
    if org_id is None and actor_id is not None:
        try:
            actor = db.session.get(User, actor_id)
            if actor:
                org_id = actor.organization_id
        except Exception:
            pass
    try:
        last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
        prev_hash = last_log.current_hash if last_log and last_log.current_hash else "GENESIS"
        
        timestamp = datetime.now()
        data_str = f"{actor_id}{action}{target_id}{details}{timestamp.isoformat()}{prev_hash}"
        current_hash = hashlib.sha256(data_str.encode('utf-8')).hexdigest()

        log = AuditLog(actor_id=actor_id, action=action,
                       target_id=target_id, details=details, org_id=org_id,
                       timestamp=timestamp, prev_hash=prev_hash, current_hash=current_hash)
        db.session.add(log)
        db.session.commit()
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)

def verify_log_chain() -> tuple[bool, str]:
    """Verify the integrity of the entire audit log chain."""
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    expected_prev = "GENESIS"
    
    for i, log in enumerate(logs):
        if log.prev_hash != expected_prev:
            return False, f"Broken chain at log ID {log.id}: prev_hash mismatch"
            
        data_str = f"{log.actor_id}{log.action}{log.target_id}{log.details}{log.timestamp.isoformat()}{log.prev_hash}"
        calc_hash = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
        
        if log.current_hash != calc_hash:
            return False, f"Tampering detected at log ID {log.id}: current_hash mismatch"
            
        expected_prev = log.current_hash
        
    return True, "Audit log integrity verified."
