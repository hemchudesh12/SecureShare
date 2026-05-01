from app import app, db, User, CryptoUtils
from config import Config
from werkzeug.security import generate_password_hash
import uuid
import os

import bcrypt

def create_admin_user():
    with app.app_context():
        if User.query.filter_by(username='admin').first():
            print("Admin user already exists.")
            return

        print("Creating admin user...")
        password = "admin123" 
        email = "admin@example.com"
        
        # Generate and Encrypt RSA Keys
        private_pem, public_pem = CryptoUtils.generate_key_pair()
        encrypted_private_key = CryptoUtils.encrypt_private_key(private_pem, password)

        # Hash Password with bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt).decode()
                
        new_user = User(
            username='admin',
            email=email,
            password_hash=password_hash,
            public_key=public_pem.decode('utf-8'),
            private_key=encrypted_private_key,
            is_admin=True
        )
        
        db.session.add(new_user)
        db.session.commit()
        print(f"Admin user created.\nUsername: admin\nEmail: {email}\nPassword: {password}")
        
        db.session.add(new_user)
        db.session.commit()
        print(f"Admin user created.\nUsername: admin\nPassword: {password}")

if __name__ == "__main__":
    create_admin_user()
