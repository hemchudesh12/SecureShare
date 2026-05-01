import bcrypt
from app import app, db
from models import User, Organization
from crypto_utils import CryptoUtils

with app.app_context():
    # check if test admin exists
    admin = User.query.filter_by(username='testadmin').first()
    if not admin:
        private_pem, public_pem = CryptoUtils.generate_key_pair()
        password = 'password123'
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        # Create an org
        org = Organization.query.filter_by(org_name='TestOrg').first()
        if not org:
            org = Organization(org_name='TestOrg', created_by=1)
            db.session.add(org)
            db.session.flush()

        new_user = User(
            username='testadmin',
            email='testadmin@example.com',
            email_verified=True,
            password_hash=password_hash,
            public_key=public_pem.decode('utf-8'),
            private_key=CryptoUtils.encrypt_private_key(private_pem, password),
            is_admin=True,
            is_approved=True,
            role='admin',
            organization_id=org.id
        )
        db.session.add(new_user)
        db.session.commit()
        print("Created testadmin")
    else:
        print("testadmin already exists")
