"""
migrate_db.py — Non-destructive database migration script for SecureShare.

Run once after pulling new code that adds or renames columns.
Existing data is NOT destroyed; only structural changes are applied.

Changes included:
  v1 — users.is_admin (auth.db), files.sender_id, files.sha256_hash (files.db)
  v2 — files.nonce → files.iv (CBC IV replaces GCM nonce) in files.db
         files.signature (add column for RSA-PSS signature)
  v3 — audit_logs.org_id (tag audit entries to an organization) in auth.db
"""
import sqlite3
from config import Config


def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


# ---------------------------------------------------------------------------
# AUTH DB migrations (users, audit_logs, etc.)
# ---------------------------------------------------------------------------

def run_auth_migrations():
    """Migrations on auth.db."""
    conn   = sqlite3.connect(Config.AUTH_DATABASE_URI)
    cursor = conn.cursor()

    # V1 — add is_admin to users
    if _column_exists(cursor, 'users', 'is_admin'):
        print("⏭️   Skip (already exists): users.is_admin")
    else:
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
        conn.commit()
        print("✅  Added column: users.is_admin")

    # V3 — add org_id to audit_logs
    if _column_exists(cursor, 'audit_logs', 'org_id'):
        print("⏭️   Skip (already exists): audit_logs.org_id")
    else:
        cursor.execute(
            "ALTER TABLE audit_logs ADD COLUMN org_id INTEGER")
        conn.commit()
        print("✅  Added column: audit_logs.org_id")

    # V4 — OTP email verification columns on users
    otp_columns = [
        ("email",          "TEXT"),
        ("email_verified", "BOOLEAN DEFAULT 0"),
        ("otp_hash",       "TEXT"),
        ("otp_expiry",     "DATETIME"),
        ("otp_attempts",   "INTEGER DEFAULT 0"),
        ("otp_last_sent",  "DATETIME"),
    ]
    for col, definition in otp_columns:
        if _column_exists(cursor, 'users', col):
            print(f"⏭️   Skip (already exists): users.{col}")
        else:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
            conn.commit()
            print(f"✅  Added column: users.{col}")

    conn.close()
    print("Auth DB migrations complete.")


# ---------------------------------------------------------------------------
# FILES DB migrations (files table)
# ---------------------------------------------------------------------------

def run_files_migrations():
    """Migrations on files.db."""
    conn   = sqlite3.connect(Config.FILES_DATABASE_URI)
    cursor = conn.cursor()

    # V1 — add columns to files
    add_columns = [
        # (column_name, column_definition)
        ("sender_id",   "INTEGER"),
        ("sha256_hash", "BLOB"),
        ("signature",   "BLOB"),
    ]

    for column, definition in add_columns:
        if _column_exists(cursor, 'files', column):
            print(f"⏭️   Skip (already exists): files.{column}")
        else:
            cursor.execute(
                f"ALTER TABLE files ADD COLUMN {column} {definition}")
            conn.commit()
            print(f"✅  Added column: files.{column}")

    # V2 — rename files.nonce → files.iv
    #
    # SQLite < 3.25 does not support RENAME COLUMN; we use the
    # SQLite-recommended table-rebuild approach for portability.
    if _column_exists(cursor, "files", "nonce") and \
       not _column_exists(cursor, "files", "iv"):
        print("🔄  Renaming files.nonce → files.iv …")
        cursor.executescript("""
            PRAGMA foreign_keys = OFF;

            BEGIN;

            CREATE TABLE files_new (
                id              INTEGER PRIMARY KEY,
                filename        VARCHAR(255) NOT NULL,
                stored_filename VARCHAR(255) NOT NULL UNIQUE,
                owner_id        INTEGER NOT NULL,
                sender_id       INTEGER,
                upload_date     DATETIME,
                file_size       INTEGER NOT NULL,
                iv              BLOB NOT NULL,
                sha256_hash     BLOB,
                signature       BLOB
            );

            INSERT INTO files_new
                (id, filename, stored_filename, owner_id, sender_id,
                 upload_date, file_size, iv, sha256_hash, signature)
            SELECT
                id, filename, stored_filename, owner_id, sender_id,
                upload_date, file_size, nonce, sha256_hash, signature
            FROM files;

            DROP TABLE files;
            ALTER TABLE files_new RENAME TO files;

            COMMIT;

            PRAGMA foreign_keys = ON;
        """)
        conn.commit()
        print("✅  Renamed files.nonce → files.iv")
    elif _column_exists(cursor, "files", "iv"):
        print("⏭️   Skip: files.iv already exists (rename already applied)")
    else:
        print("⚠️   files.nonce not found — table may be freshly created (OK)")

    conn.close()
    print("Files DB migrations complete.")


if __name__ == "__main__":
    run_auth_migrations()
    run_files_migrations()
    print("\nAll migrations complete.")
