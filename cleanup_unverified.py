"""
cleanup_unverified.py — Remove all unverified user records from auth.db.

Deletes users where email_verified = 0 (False), along with their related
OrgRequest, AuditLog, and LoginLog records.

Usage:
    python cleanup_unverified.py
"""

import sqlite3
from config import Config


def cleanup():
    conn = sqlite3.connect(Config.AUTH_DATABASE_URI)
    cursor = conn.cursor()

    # Find unverified users
    cursor.execute(
        "SELECT id, username, email FROM users WHERE email_verified = 0 OR email_verified IS NULL"
    )
    unverified = cursor.fetchall()

    if not unverified:
        print("✅ No unverified user records found. Database is clean.")
        conn.close()
        return

    print(f"Found {len(unverified)} unverified user(s):")
    for uid, uname, email in unverified:
        print(f"  • id={uid}  username={uname}  email={email}")

    user_ids = [row[0] for row in unverified]
    placeholders = ",".join("?" * len(user_ids))

    # Delete related records
    cursor.execute(
        f"DELETE FROM organization_requests WHERE user_id IN ({placeholders})",
        user_ids,
    )
    org_req_count = cursor.rowcount
    print(f"  Deleted {org_req_count} organization request(s)")

    cursor.execute(
        f"DELETE FROM audit_logs WHERE actor_id IN ({placeholders})",
        user_ids,
    )
    audit_count = cursor.rowcount
    print(f"  Deleted {audit_count} audit log(s)")

    cursor.execute(
        f"DELETE FROM login_logs WHERE user_id IN ({placeholders})",
        user_ids,
    )
    login_count = cursor.rowcount
    print(f"  Deleted {login_count} login log(s)")

    # Delete the users themselves
    cursor.execute(
        f"DELETE FROM users WHERE id IN ({placeholders})",
        user_ids,
    )
    user_count = cursor.rowcount
    print(f"  Deleted {user_count} user record(s)")

    conn.commit()
    conn.close()

    print(f"\n✅ Cleanup complete: {user_count} unverified user(s) removed.")


if __name__ == "__main__":
    cleanup()
