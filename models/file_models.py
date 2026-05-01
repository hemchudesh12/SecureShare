from datetime import datetime
from extensions import db

class File(db.Model):
    __tablename__ = 'files'
    __bind_key__  = 'files_db'

    id              = db.Column(db.Integer, primary_key=True)
    filename        = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    owner_id        = db.Column(db.Integer, nullable=False)   # User.id
    sender_id       = db.Column(db.Integer, nullable=True)
    upload_date     = db.Column(db.DateTime, default=datetime.now)
    file_size       = db.Column(db.Integer, nullable=False)

    # Cryptographic metadata
    iv                = db.Column(db.LargeBinary, nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=True)
    digital_signature = db.Column(db.Text, nullable=True)     # Base64 RSA-PSS sig

class FileShare(db.Model):
    __tablename__ = 'file_keys'
    __bind_key__  = 'files_db'

    id                = db.Column(db.Integer, primary_key=True)
    file_id           = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    user_id           = db.Column(db.Integer, nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
    
    # Access control
    expiry_time       = db.Column(db.DateTime, nullable=True)
    download_limit    = db.Column(db.Integer, nullable=True)
    download_count    = db.Column(db.Integer, default=0, nullable=False)
    is_revoked        = db.Column(db.Boolean, default=False, nullable=False)

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    __bind_key__  = 'files_db'

    id                  = db.Column(db.Integer, primary_key=True)
    file_id             = db.Column(db.Integer, nullable=False)
    user_id             = db.Column(db.Integer, nullable=False)
    access_time         = db.Column(db.DateTime, default=datetime.now)
    ip_address          = db.Column(db.String(45), nullable=True)
    verification_status = db.Column(db.String(50), nullable=False)

class VerificationLog(db.Model):
    __tablename__ = 'verification_logs'
    __bind_key__  = 'files_db'

    id                  = db.Column(db.Integer, primary_key=True)
    file_id             = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    verified_by         = db.Column(db.Integer, nullable=False)
    verification_status = db.Column(db.String(20), nullable=False)  # VALID | INVALID
    verification_time   = db.Column(db.DateTime, default=datetime.now)
    ip_address          = db.Column(db.String(45), nullable=True)
