"""
celery_app.py — Celery instance and Flask-context binder for SecureShare.

Design (two-phase init — avoids circular imports):
  Phase 1: A standalone `celery` instance is created here at import time.
           tasks.py imports it directly from this module.
           No reference to app.py is needed at this stage.

  Phase 2: init_celery(app) is called from app.py after create_app()
           returns.  It pushes the Flask config into Celery and wraps
           every task execution in a Flask app-context push.

Deployment:
  # Run Redis:  docker run -d -p 6379:6379 redis:7-alpine
  # Run worker (Windows):   celery -A worker worker --pool=solo --loglevel=info
  # Run worker (Linux/Mac): celery -A worker worker --loglevel=info --concurrency=4
  # Run Flask:  flask run
"""

from celery import Celery

# ── Phase 1: standalone instance ─────────────────────────────────────────────
# Broker / backend are configured in Phase 2 once Flask config is available.
# Default broker is Redis. init_celery() will override with Flask config.
celery = Celery('secure_file_sharing', broker='redis://localhost:6379/0')


# ── Phase 2: Flask-context binder ────────────────────────────────────────────

def init_celery(app):
    """Bind the standalone Celery instance to the Flask application.

    Called once from app.py immediately after create_app() returns.
    Maps Flask CELERY_* config keys to Celery 5.x lowercase equivalents,
    then wraps every task execution in a Flask app-context push.
    """
    # Celery 5.x uses lowercase keys (broker_url, result_backend).
    # The old CELERY_BROKER_URL / CELERY_RESULT_BACKEND names are deprecated
    # and the broker one is silently ignored, causing AMQP fallback.
    celery.conf.broker_url = app.config.get(
        'CELERY_BROKER_URL', 'redis://localhost:6379/0'
    )
    celery.conf.result_backend = app.config.get(
        'CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'
    )
    celery.conf.task_serializer   = 'json'
    celery.conf.result_serializer = 'json'
    celery.conf.accept_content    = ['json']

    class ContextTask(celery.Task):
        """Task subclass that pushes a Flask app context for every execution."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return super().__call__(*args, **kwargs)

    celery.Task = ContextTask

