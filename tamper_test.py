import os
import requests
import sqlite3
from config import Config

# Configuration for the test
BASE_URL = "http://127.0.0.1:5000"
TEST_USER = "testuser"
TEST_PASS = "testpass123"
TEST_EMAIL = "test@example.com"

def run_tamper_test():
    session = requests.Session()
    
    print("\n--- 🛡️  SIGNATURE TAMPER TEST CASE ---")
    
    # 1. Register and Login
    print("[1] Registering and logging in...")
    reg_data = {"username": TEST_USER, "email": TEST_EMAIL, "password": TEST_PASS}
    session.post(f"{BASE_URL}/register", data=reg_data)
    login_data = {"username": TEST_USER, "password": TEST_PASS}
    session.post(f"{BASE_URL}/login", data=login_data)
    
    # 2. Upload a file
    print("[2] Uploading file 'test.txt'...")
    with open("test.txt", "w") as f:
        f.write("This is a highly confidential document.")
    
    with open("test.txt", "rb") as f:
        session.post(f"{BASE_URL}/upload", files={"file": f}, data={"recipients": []})
    
    # 3. Find the file on disk
    print("[3] Identifiying encrypted file on disk...")
    # We query the database to find the stored filename
    conn = sqlite3.connect(Config.FILES_DATABASE_URI)
    cursor = conn.cursor()
    cursor.execute("SELECT stored_filename FROM files ORDER BY id DESC LIMIT 1")
    stored_name = cursor.fetchone()[0]
    conn.close()
    
    enc_path = os.path.join(Config.FILES_DIR, stored_name)
    print(f"    Encrypted path: {enc_path}")
    
    # 4. Tamper with the file
    print("[4] ⚠️  Tampering with the encrypted file (flipping a bit)...")
    with open(enc_path, "r+b") as f:
        f.seek(50) # Skip IV
        byte = f.read(1)
        f.seek(50)
        f.write(bytes([ord(byte) ^ 0xFF]))
    
    # 5. Attempt Download
    print("[5] Attempting download/verification...")
    cursor = sqlite3.connect(Config.FILES_DATABASE_URI).cursor()
    cursor.execute("SELECT id FROM files ORDER BY id DESC LIMIT 1")
    file_id = cursor.fetchone()[0]
    
    # standalone verify
    response = session.get(f"{BASE_URL}/verify/{file_id}")
    if "Signature Invalid – File Tampered" in response.text:
        print("\n✅ SUCCESS: The system detected the tampering!")
        print("   Result: Signature Invalid – File Integrity Compromised")
    else:
        print("\n❌ FAILURE: The system did NOT detect the tampering.")
        print("   Verification Logic is bypassable or fake.")

    # Cleanup
    if os.path.exists("test.txt"): os.remove("test.txt")

if __name__ == "__main__":
    print("Ensure the Flask app is running before starting this test.")
    try:
        run_tamper_test()
    except Exception as e:
        print(f"Error: {e}")
