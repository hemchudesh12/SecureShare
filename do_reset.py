"""
do_reset.py — Non-interactive full reset: deletes auth.db, files.db and all encrypted files.
"""
import os, shutil, sys
sys.path.insert(0, os.path.dirname(__file__))
from config import Config

print("=" * 55)
print("  SecureShare — Full Database & File Reset")
print("=" * 55)

# Delete databases
for db_path in [Config.AUTH_DATABASE_URI, Config.FILES_DATABASE_URI]:
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"  ✅ DELETED: {db_path}")
    else:
        print(f"  ℹ️  NOT FOUND (skip): {db_path}")

# Delete all files in storage/files/
files_dir = Config.FILES_DIR
count = 0
if os.path.isdir(files_dir):
    for fname in os.listdir(files_dir):
        fpath = os.path.join(files_dir, fname)
        try:
            os.remove(fpath)
            count += 1
        except Exception as e:
            print(f"  ⚠️  Could not delete {fpath}: {e}")
print(f"  ✅ Deleted {count} encrypted file(s) from storage/files/")

print()
print("  Done. Run 'python app.py' to recreate the DB schema.")
print("=" * 55)
