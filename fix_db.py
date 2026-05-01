import sqlite3
import os

db_path = os.path.join("storage", "auth.db")

print(f"Connecting to {db_path}...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash VARCHAR(64);")
    print("Added prev_hash column.")
except sqlite3.OperationalError as e:
    print(f"Error adding prev_hash: {e}")

try:
    cursor.execute("ALTER TABLE audit_logs ADD COLUMN current_hash VARCHAR(64);")
    print("Added current_hash column.")
except sqlite3.OperationalError as e:
    print(f"Error adding current_hash: {e}")

conn.commit()
conn.close()
print("Done.")
