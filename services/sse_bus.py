"""
services/sse_bus.py
-------------------
Lightweight in-process pub/sub bus for Server-Sent Events.

Each file owner has a list of subscriber queues.  When a download occurs,
file_service calls notify_download_update(owner_id, payload) which pushes
the event to every open SSE connection for that owner.

Design notes
------------
- Pure stdlib — no Redis, no Celery, no threads required.
- Works with Flask's development server (threaded=True) and Gunicorn with
  sync/gthread workers.  Does NOT work with async/gevent workers.
- Queues are cleaned up automatically when the SSE connection closes.
"""

import queue
import threading
from typing import Dict, List

_lock: threading.Lock = threading.Lock()
# { owner_id -> [Queue, ...] }
_subscribers: Dict[int, List[queue.Queue]] = {}

_SENTINEL = object()   # pushed to signal connection close


def subscribe(owner_id: int) -> queue.Queue:
    """Register a new SSE listener for *owner_id* and return its queue."""
    q: queue.Queue = queue.Queue(maxsize=50)
    with _lock:
        _subscribers.setdefault(owner_id, []).append(q)
    return q


def unsubscribe(owner_id: int, q: queue.Queue) -> None:
    """Remove a queue when the SSE connection closes."""
    with _lock:
        buckets = _subscribers.get(owner_id, [])
        try:
            buckets.remove(q)
        except ValueError:
            pass
        if not buckets:
            _subscribers.pop(owner_id, None)


def notify_download_update(owner_id: int, share_id: int,
                           download_count: int, download_limit,
                           is_revoked: bool) -> None:
    """Push a download-count update to every subscriber of *owner_id*."""
    payload = {
        'share_id':      share_id,
        'download_count': download_count,
        'download_limit': download_limit,
        'is_revoked':     is_revoked,
    }
    with _lock:
        buckets = list(_subscribers.get(owner_id, []))

    dead: list = []
    for q in buckets:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)

    # Silently drop full queues (slow consumers)
    if dead:
        with _lock:
            for q in dead:
                try:
                    _subscribers.get(owner_id, []).remove(q)
                except ValueError:
                    pass
