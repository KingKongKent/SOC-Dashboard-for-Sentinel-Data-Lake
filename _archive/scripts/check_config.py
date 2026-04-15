#!/usr/bin/env python3
"""Temporary diagnostic: dump config table contents."""
import sqlite3, os, sys

db = "/var/lib/soc-dashboard/soc_dashboard.db"
print(f"DB exists: {os.path.exists(db)}, size: {os.path.getsize(db) if os.path.exists(db) else 'N/A'}")

conn = sqlite3.connect(db)
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
print(f"Tables: {[r[0] for r in cur.fetchall()]}")

try:
    cur.execute("SELECT key, value, is_encrypted FROM config ORDER BY key")
    rows = cur.fetchall()
    print(f"\nConfig rows: {len(rows)}")
    for key, val, enc in rows:
        display = val[:50] + "..." if val and len(val) > 50 else val
        print(f"  {key:35s} = {display!r:55s}  enc={enc}")
except Exception as e:
    print(f"Config table error: {e}")

conn.close()
