#!/usr/bin/env python3
"""Test the encryption migration on the server."""
import sys
sys.path.insert(0, '/opt/soc-dashboard')
import os
os.chdir('/opt/soc-dashboard')

# Load the same env as the service
from dotenv import load_dotenv
load_dotenv('/etc/soc-dashboard/.env')

import sqlite3
from config_manager import _get_db_path, _decrypt, _get_fernet, SECRET_KEYS, _ensure_table

db = _get_db_path()
print(f"DB path: {db}")
print(f"SECRET_KEYS: {SECRET_KEYS}")

conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute('SELECT key, value, is_encrypted FROM config WHERE is_encrypted = 1')
rows = cur.fetchall()
print(f"\nEncrypted rows: {len(rows)}")
for row in rows:
    key = row['key']
    should_enc = key in SECRET_KEYS
    print(f"  {key}: in SECRET_KEYS={should_enc}")
    if not should_enc:
        print(f"    -> NEEDS MIGRATION")
        try:
            plain = _decrypt(row['value'])
            print(f"    -> Decrypted OK: {plain[:40]}...")
        except Exception as e:
            print(f"    -> Decrypt FAILED: {e}")
conn.close()

# Now trigger actual migration
print("\nRunning _ensure_table (which triggers _migrate_encryption)...")
_ensure_table()
print("Done.")

# Re-check
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute('SELECT key, value, is_encrypted FROM config WHERE key = ?', ('FOUNDRY_ENDPOINT',))
row = cur.fetchone()
if row:
    print(f"\nFOUNDRY_ENDPOINT: enc={row['is_encrypted']}, value={row['value'][:50]}...")
conn.close()
