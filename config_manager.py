"""
Configuration Manager for SOC Dashboard
Stores settings in SQLite with Fernet encryption for secrets.
DB config takes precedence over .env values.
"""

import os
import sqlite3
from datetime import datetime
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# Keys that contain secrets and must be encrypted in the DB
SECRET_KEYS = frozenset({
    'CLIENT_SECRET',
    'VIRUSTOTAL_API_KEY',
    'TALOS_API_KEY',
    'ABUSEIPDB_API_KEY',
    'SECRET_KEY',
})

# All configurable keys (shown on settings page)
CONFIGURABLE_KEYS = [
    # API Credentials
    'CLIENT_ID',
    'CLIENT_SECRET',
    'TENANT_ID',
    # Sentinel
    'SENTINEL_WORKSPACE_ID',
    'SENTINEL_WORKSPACE_NAME',
    # Threat Intel
    'VIRUSTOTAL_API_KEY',
    'TALOS_API_KEY',
    'ABUSEIPDB_API_KEY',
    # Operational
    'REFRESH_INTERVAL_MINUTES',
    # Access Control
    'ADMIN_USERS',
    # Escalation
    'ESCALATION_EMAIL',
]


def _get_db_path() -> str:
    return os.getenv('DB_PATH', 'soc_dashboard.db')


def _get_key_path() -> str:
    return os.getenv('CONFIG_KEY_PATH',
                     os.path.join(os.path.dirname(_get_db_path()), '.encryption_key'))


def _load_or_create_key() -> bytes:
    """Load the Fernet key from disk, or create one on first run."""
    key_path = _get_key_path()
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read().strip()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(key_path) or '.', exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    print(f"🔑 Generated new encryption key at {key_path}")
    return key


_fernet = None

def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def _encrypt(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def _decrypt(token: str) -> str:
    return _get_fernet().decrypt(token.encode()).decode()


# ── CRUD ────────────────────────────────────────

def get_config(key: str, default: str | None = None) -> str | None:
    """
    Get a config value.  Priority: DB → os.environ → default.
    Decrypts transparently if the value is stored encrypted.
    """
    try:
        conn = sqlite3.connect(_get_db_path())
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT value, is_encrypted FROM config WHERE key = ?', (key,))
        row = cur.fetchone()
        conn.close()
        if row and row['value']:
            val = row['value']
            if row['is_encrypted']:
                val = _decrypt(val)
            return val
    except Exception:
        pass

    env_val = os.getenv(key, '').strip()
    return env_val if env_val else default


def set_config(key: str, value: str, encrypt: bool | None = None) -> None:
    """
    Upsert a config value.  If *encrypt* is None, auto-detect from SECRET_KEYS.
    """
    if encrypt is None:
        encrypt = key in SECRET_KEYS

    stored = _encrypt(value) if encrypt else value
    is_enc = 1 if encrypt else 0

    conn = sqlite3.connect(_get_db_path())
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO config (key, value, is_encrypted, updated_at) '
        'VALUES (?, ?, ?, ?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value, '
        'is_encrypted=excluded.is_encrypted, updated_at=excluded.updated_at',
        (key, stored, is_enc, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_all_config() -> list[dict]:
    """
    Return all configurable keys with their values.
    Secret values are masked as '••••••••'.
    """
    result = []
    for key in CONFIGURABLE_KEYS:
        raw = get_config(key)
        is_secret = key in SECRET_KEYS
        result.append({
            'key': key,
            'value': '••••••••' if (is_secret and raw) else (raw or ''),
            'hasValue': bool(raw),
            'isSecret': is_secret,
        })
    return result


def delete_config(key: str) -> None:
    conn = sqlite3.connect(_get_db_path())
    cur = conn.cursor()
    cur.execute('DELETE FROM config WHERE key = ?', (key,))
    conn.commit()
    conn.close()
