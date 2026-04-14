#!/usr/bin/env python3
"""
One-time migration: rewrite legacy status values to canonical form.

    Resolved  →  Closed
    InProgress / inProgress  →  Active

Updates both the `status` column and the JSON `data` blob in the
incidents table so stored data is fully canonical (not just
compatibility-filtered at query time).

Safe to run multiple times — only touches non-canonical rows.

Usage:
    python scripts/migrate_status_canonical.py          # dry-run (default)
    python scripts/migrate_status_canonical.py --apply  # commit changes
"""

import json
import os
import sqlite3
import sys

DB_FILE = os.getenv("DB_PATH", "soc_dashboard.db")

# Legacy value (case-insensitive match) → canonical replacement
_MIGRATIONS = {
    "resolved": "Closed",
    "inprogress": "Active",
}


def migrate(apply: bool = False) -> None:
    if not os.path.exists(DB_FILE):
        print(f"❌ Database not found: {DB_FILE}")
        sys.exit(1)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT id, status, data FROM incidents WHERE LOWER(status) IN (?, ?)",
        tuple(_MIGRATIONS.keys()),
    ).fetchall()

    if not rows:
        print("✅ No legacy status values found — nothing to migrate.")
        conn.close()
        return

    print(f"{'🔍 DRY-RUN' if not apply else '🔧 APPLYING'}: "
          f"{len(rows)} incident(s) to update\n")

    for row in rows:
        old_status = row["status"]
        new_status = _MIGRATIONS[old_status.lower()]
        print(f"  {row['id']:>30s}  {old_status:<12s} → {new_status}")

        if apply:
            # Update column
            conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (new_status, row["id"]),
            )
            # Patch JSON blob
            try:
                blob = json.loads(row["data"])
                blob["status"] = new_status
                conn.execute(
                    "UPDATE incidents SET data = ? WHERE id = ?",
                    (json.dumps(blob), row["id"]),
                )
            except (json.JSONDecodeError, TypeError):
                pass  # blob missing or corrupt — column still updated

    if apply:
        conn.commit()
        print(f"\n✅ Migrated {len(rows)} incident(s).")
    else:
        print(f"\n⚠️  Dry-run complete. Re-run with --apply to commit changes.")

    conn.close()


if __name__ == "__main__":
    migrate(apply="--apply" in sys.argv)
