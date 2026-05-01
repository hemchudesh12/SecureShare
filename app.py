"""
app.py — SecureShare: Org-Scoped Encrypted File Sharing

Security model:
  - AES-256-CBC chunk-based (O(1) RAM) file encryption
  - RSA-2048/OAEP to wrap per-file AES keys per recipient
  - RSA-2048/PSS + SHA-256 digital signatures (mandatory on download)
  - Organization-scoped: only same-org members can share files
  - Admin approval workflow
  - Encrypted private key storage (PBKDF2 + AES-256)
  - Audit logging for all sensitive actions
  - Rate limiting on auth endpoints
"""
import logging
from flask import Flask

from extensions import db, csrf, limiter
from config import Config
from routes import register_routes
from models import User
from services.crypto_service import CryptoUtils
import bcrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    from extensions import init_db
    init_db(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register routes
    register_routes(app)

    return app

app = create_app()

# Bind the standalone Celery instance to this Flask app — must come after
# create_app() so app.config is fully populated with broker/backend URLs.
from celery_app import init_celery  # noqa: E402
init_celery(app)


@app.cli.command("create-admin")
def create_admin():
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")

    if User.query.filter_by(username=username).first():
        print("User already exists.")
        return

    private_pem, public_pem = CryptoUtils.generate_key_pair()
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_user = User(
        username=username,
        password_hash=password_hash,
        public_key=public_pem.decode('utf-8'),
        private_key=CryptoUtils.encrypt_private_key(private_pem, password),
        is_admin=True,
        is_approved=True,
        role='admin'
    )
    db.session.add(new_user)
    db.session.commit()
    print(f"Admin '{username}' created (id={new_user.id}).")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, threaded=True)
