import os
import uuid
from werkzeug.utils import secure_filename
from models import User, File, FileShare, VerificationLog, AccessLog
from extensions import db
from services.logging_service import log_event
from services.crypto_service import CryptoUtils
from services import sse_bus
from config import Config
from utils.helpers import _safe_remove

def process_upload(user, uploaded_file, recipient_ids_set, session_p_key, expiry_time=None, download_limit=None):
    try:
        sender_private_pem = CryptoUtils.decrypt_private_key(user.private_key, session_p_key)
    except Exception:
        return False, "Session key error. Please log in again."

    stored_name   = str(uuid.uuid4())
    enc_path      = os.path.join(Config.FILES_DIR, stored_name)
    tmp_plain_path = os.path.join(Config.FILES_DIR, f"{stored_name}.plain")

    try:
        uploaded_file.save(tmp_plain_path)

        aes_key, _, file_hash = CryptoUtils.encrypt_file_chunked(tmp_plain_path, enc_path)
        file_size = os.path.getsize(tmp_plain_path)
        signature_b64 = CryptoUtils.sign_hash(file_hash, sender_private_pem)

        new_file = File(
            filename=secure_filename(uploaded_file.filename),
            stored_filename=stored_name,
            owner_id=user.id,
            sender_id=user.id,
            file_size=file_size,
            iv=b'',          # GCM nonces are embedded per-chunk in the file; no per-file IV needed
            digital_signature=signature_b64,
        )
        db.session.add(new_file)
        db.session.flush()

        for rid in recipient_ids_set:
            recipient = db.session.get(User, rid)
            if not recipient or not recipient.public_key:
                continue
            enc_aes_key = CryptoUtils.encrypt_aes_key(aes_key, recipient.public_key)
            db.session.add(FileShare(
                file_id=new_file.id,
                user_id=recipient.id,
                encrypted_aes_key=enc_aes_key,
                expiry_time=expiry_time,
                download_limit=download_limit
            ))

        db.session.commit()
        log_event(user.id, 'FILE_UPLOADED', target_id=new_file.id,
                  details=f'size={file_size}, recipients={len(recipient_ids_set)}')
        
        return True, f'✅ "{new_file.filename}" encrypted, signed & shared with {len(recipient_ids_set)} recipient(s).'
    except Exception as exc:
        db.session.rollback()
        return False, f'Upload failed: {exc}'
    finally:
        _safe_remove(tmp_plain_path)

def process_download(user, file_record, share_record, session_p_key, remote_addr):
    """
    Secure streaming download pipeline.

    Security guarantees (MANDATORY — do not weaken):
      1. Digital signature is verified BEFORE any bytes are yielded to the client.
      2. No decrypted plaintext is ever written to disk.
      3. Memory usage is O(CHUNK_SIZE) — one 64 KB block at a time.
      4. A single AES cipher context is maintained across chunks (never re-initialised).

    Returns:
      (True,  generator)  — generator yields decrypted bytes ready for streaming.
      (False, error_str)  — caller must NOT stream; show error to user.
    """
    sender   = db.session.get(User, file_record.sender_id)
    enc_path = os.path.join(Config.FILES_DIR, file_record.stored_filename)

    try:
        # ── Step 1: Recover the per-file AES session key ───────────────────
        private_key_pem = CryptoUtils.decrypt_private_key(user.private_key, session_p_key)
        aes_key         = CryptoUtils.decrypt_aes_key(share_record.encrypted_aes_key, private_key_pem)

        # ── Step 2: Compute SHA-256 of plaintext WITHOUT writing to disk ───
        #    GCM nonces are embedded per-chunk; iv argument is b'' and ignored internally.
        recomputed_hash = CryptoUtils.compute_plaintext_hash_stream(enc_path, aes_key, b'')

        # ── Step 3: Verify digital signature BEFORE streaming ──────────────
        if not sender or not sender.public_key:
            raise ValueError("Sender public key unavailable — cannot verify.")

        is_valid = CryptoUtils.verify_hash_signature(
            recomputed_hash, file_record.digital_signature, sender.public_key
        )

        # ── Audit logging ──────────────────────────────────────────────────
        db.session.add(AccessLog(
            file_id=file_record.id,
            user_id=user.id,
            ip_address=remote_addr,
            verification_status="VALID" if is_valid else "INVALID"
        ))
        db.session.add(VerificationLog(
            file_id=file_record.id,
            verified_by=user.id,
            verification_status="VALID" if is_valid else "INVALID",
            ip_address=remote_addr,
        ))

        if not is_valid:
            db.session.commit()
            log_event(user.id, 'SIGNATURE_INVALID', target_id=file_record.id,
                      details='Tamper detected on download')
            raise ValueError("❌ Signature Invalid — File Integrity Compromised")

        share_record.download_count += 1
        db.session.commit()
        log_event(user.id, 'FILE_DOWNLOADED', target_id=file_record.id)

        # ── Push real-time SSE update to the file owner ────────────────────
        sse_bus.notify_download_update(
            owner_id       = file_record.owner_id,
            share_id       = share_record.id,
            download_count = share_record.download_count,
            download_limit = share_record.download_limit,
            is_revoked     = share_record.is_revoked,
        )

        # ── Step 4: Return streaming generator (no disk write) ─────────────
        #    The generator is NOT started here; Flask iterates it after this
        #    function returns. GCM nonces are embedded per-chunk; iv is b''.
        return True, CryptoUtils.stream_decrypt(enc_path, aes_key, b'')

    except Exception as exc:
        return False, str(exc)

def revoke_access(file_id: int, recipient_id: int, actor: User) -> tuple[bool, str]:
    file_record = db.session.get(File, file_id)
    if not file_record or file_record.sender_id != actor.id:
        return False, "Not authorized to revoke access for this file."
    
    share = FileShare.query.filter_by(file_id=file_id, user_id=recipient_id).first()
    if not share:
        return False, "Share record not found."
    
    share.is_revoked = True
    db.session.commit()
    log_event(actor.id, "ACCESS_REVOKED", target_id=file_id, details=f"recipient_id={recipient_id}")
    return True, "Access revoked successfully."

def get_access_history(file_id: int) -> list[AccessLog]:
    return AccessLog.query.filter_by(file_id=file_id).order_by(AccessLog.access_time.desc()).all()
