"""
worker.py — Celery worker entry point for SecureShare.

Import order matters:
  1. `from app import app`  — runs app.py top-to-bottom, which calls
                             init_celery(app).  The standalone celery instance
                             in celery_app.py is now fully configured with the
                             Flask broker URL and ContextTask wrapper.
  2. `from celery_app import celery` — re-exports the configured instance
                             so the Celery CLI can find it as `worker.celery`.

Usage:
  # Windows (pool=solo avoids multiprocessing fork issues on Windows):
  celery -A worker worker --pool=solo --loglevel=info

  # Linux / macOS:
  celery -A worker worker --loglevel=info --concurrency=4
"""

# Step 1: import the app MODULE (triggers create_app + init_celery).
# Aliased to '_' so the Flask 'app' object is NOT exposed as a module-level
# name — Celery CLI scans for an attribute called 'app' and would mistake
# the Flask object for the Celery app if the name were exported.
import app as _  # noqa: F401

# Step 2: expose the Celery instance — CLI finds it via 'worker:celery'
from celery_app import celery  # noqa: F401

