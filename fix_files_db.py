import sqlite3
import os

db_path = os.path.join("storage", "files.db")

print(f"Connecting to {db_path}...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

columns_to_add = [
    ("expiry_time", "DATETIME"),
    ("download_limit", "INTEGER"),
    ("download_count", "INTEGER NOT NULL DEFAULT 0"),
    ("is_revoked", "BOOLEAN NOT NULL DEFAULT 0")
]

for col_name, col_type in columns_to_add:
    try:
        cursor.execute(f"ALTER TABLE file_keys ADD COLUMN {col_name} {col_type};")
        print(f"Added {col_name} column.")
    except sqlite3.OperationalError as e:
        print(f"Error adding {col_name}: {e}")

conn.commit()
conn.close()
print("Done.")
