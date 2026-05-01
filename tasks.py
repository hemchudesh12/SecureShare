"""
tasks.py — Celery tasks for SecureShare.

Async upload pipeline:
  1. Temp file already saved to disk by the route before this task is queued.
  2. Task reconstructs User ORM objects from IDs (safe inside app context).
  3. Delegates to the existing process_upload() — no duplication of logic.
  4. Progress states are emitted so the frontend progress bar stays accurate.
  5. On any failure the temp file is cleaned up and the exception re-raised
     so Celery marks the task FAILURE and the frontend shows an error.
"""

import os
import logging
from datetime import datetime

from celery_app import celery  # standalone instance — no reference to app.py (avoids circular import)

from extensions import db
from models import User
from services.file_service import process_upload
from utils.helpers import _safe_remove

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Thin file-like wrapper so process_upload() can call .save() on an already-
# saved temp file without needing the original Werkzeug FileStorage object.
# ---------------------------------------------------------------------------

class _DiskFile:
    """Minimal file-like object that wraps an already-saved temp path.

    process_upload() calls:
      • uploaded_file.save(tmp_plain_path)   — we make this a no-op rename
      • uploaded_file.filename               — we expose the original filename

    Because the temp file IS already on disk we just rename it to whatever
    path process_upload() asks for, then leave the rest to the existing logic.
    """

    def __init__(self, temp_path: str, original_filename: str):
        self._temp_path = temp_path
        self.filename   = original_filename

    def save(self, dst_path: str) -> None:
        """Move the already-saved temp file to the destination path."""
        if os.path.abspath(self._temp_path) != os.path.abspath(dst_path):
            os.replace(self._temp_path, dst_path)
        # If src == dst (shouldn't happen) just leave it in place.


# ---------------------------------------------------------------------------
# Async upload task
# ---------------------------------------------------------------------------

@celery.task(bind=True)
def async_upload(
    self,
    temp_path: str,
    original_filename: str,
    owner_id: int,
    sender_id: int,
    recipient_ids: list,
    session_password: str,
    expiry_iso: str,
    download_limit: int | None,
):
    """Encrypt, sign, and store an uploaded file asynchronously.

    Args:
        temp_path:          Absolute path to the already-saved temp file.
        original_filename:  Original filename from the browser upload.
        owner_id:           User.id of the uploading user.
        sender_id:          User.id of the sender (same as owner_id).
        recipient_ids:      List of User.id strings/ints to share with.
        session_password:   Plain-text login password (used to decrypt
                            the sender's RSA private key envelope).
        expiry_iso:         ISO-format expiry datetime string, or ''.
        download_limit:     Per-recipient download cap, or None.

    Returns:
        {'status': 'done', 'redirect': '/my-files'}

    Raises:
        Any exception from process_upload() — Celery marks task FAILURE.
    """
    try:
        # ── 5 %  Starting ────────────────────────────────────────────────
        self.update_state(state='PROGRESS',
                          meta={'percent': 5, 'msg': 'Starting encryption'})

        # ── Reconstruct User objects from IDs ────────────────────────────
        owner  = db.session.get(User, int(owner_id))
        sender = db.session.get(User, int(sender_id))
        if not owner or not sender:
            raise ValueError(f"User not found: owner_id={owner_id}")

        # Build the validated recipient set (always include self)
        recipient_ids_set = {owner.id}
        for rid in recipient_ids:
            try:
                candidate = db.session.get(User, int(rid))
                if (candidate
                        and candidate.is_approved
                        and candidate.organization_id == owner.organization_id):
                    recipient_ids_set.add(candidate.id)
            except (ValueError, TypeError):
                continue

        # ── 30 %  Encrypting file ─────────────────────────────────────────
        self.update_state(state='PROGRESS',
                          meta={'percent': 30, 'msg': 'Encrypting file'})

        # Parse expiry
        expiry_time = None
        if expiry_iso:
            try:
                expiry_time = datetime.fromisoformat(expiry_iso)
            except (ValueError, TypeError):
                pass

        # Wrap the already-saved temp file in a thin adapter so
        # process_upload() can call .save() without re-uploading.
        disk_file = _DiskFile(temp_path, original_filename)

        # ── 60 %  Wrapping keys ───────────────────────────────────────────
        self.update_state(state='PROGRESS',
                          meta={'percent': 60, 'msg': 'Wrapping keys for recipients'})

        # Delegate to the existing synchronous upload pipeline.
        # process_upload() will call disk_file.save(tmp_plain_path) which
        # atomically renames our temp file to the expected location, then
        # proceeds with encryption, signing, and DB writes.
        success, message = process_upload(
            user             = owner,
            uploaded_file    = disk_file,
            recipient_ids_set= recipient_ids_set,
            session_p_key    = session_password,
            expiry_time      = expiry_time,
            download_limit   = download_limit,
        )

        # ── 85 %  Saving records ──────────────────────────────────────────
        self.update_state(state='PROGRESS',
                          meta={'percent': 85, 'msg': 'Saving file records'})

        if not success:
            raise RuntimeError(message)

        # ── 95 %  Finalising ──────────────────────────────────────────────
        self.update_state(state='PROGRESS',
                          meta={'percent': 95, 'msg': 'Finalising'})

        logger.info("async_upload succeeded: file=%s owner=%s", original_filename, owner_id)
        # Celery sets state → SUCCESS automatically on return.
        return {'status': 'done', 'redirect': '/my-files'}

    except Exception as exc:
        logger.error("async_upload failed: %s", exc, exc_info=True)
        # Clean up temp file so we don't leave orphaned blobs on disk.
        _safe_remove(temp_path)
        raise
