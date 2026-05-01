"""
reset_db.py — Wipe databases and storage for a clean slate.

Run this whenever you need to restart with a fresh schema,
for example after model changes that are not backwards-compatible.
After running, start the app with:  python app.py
Then create an admin with:  flask create-admin
"""

import os
import shutil
from config import Config


def reset_databases():
    print("=" * 55)
    print("  SecureShare — Database Reset Utility")
    print("=" * 55)

    db_files = [Config.AUTH_DATABASE_URI, Config.FILES_DATABASE_URI]
    for db_path in db_files:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
                print(f"  ✅ DELETED: {db_path}")
            except Exception as exc:
                print(f"  ❌ ERROR deleting {db_path}: {exc}")
        else:
            print(f"  ℹ️  NOT FOUND (skip): {db_path}")

    # Optionally clean uploaded files
    choice = input("\nAlso delete all uploaded encrypted files? [y/N]: ").strip().lower()
    if choice == 'y':
        files_dir = Config.FILES_DIR
        count = 0
        for fname in os.listdir(files_dir):
            fpath = os.path.join(files_dir, fname)
            try:
                os.remove(fpath)
                count += 1
            except Exception:
                pass
        print(f"  ✅ Deleted {count} file(s) from {files_dir}")

    print()
    print("  Next steps:")
    print("    1. python app.py        ← recreates DB schema")
    print("    2. flask create-admin   ← create your admin account")
    print("=" * 55)


if __name__ == "__main__":
    confirm = input("This will DELETE all data. Type 'yes' to confirm: ").strip()
    if confirm.lower() == 'yes':
        reset_databases()
    else:
        print("Aborted.")
