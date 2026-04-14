"""
Sentinel KQL Query Engine for SOC Dashboard
Executes KQL queries against Log Analytics REST API.
"""

import logging
import re
import requests
from config_manager import get_config

log = logging.getLogger(__name__)

LOG_ANALYTICS_BASE = 'https://api.loganalytics.io/v1'

# ── Token cache (module-level, same pattern as fetch_live_data.py) ──────────

_token_cache: dict = {}


def _get_log_analytics_token() -> str:
    """Acquire a client-credentials token for Log Analytics API."""
    import time
    cached = _token_cache.get('log_analytics')
    if cached and cached['expires_at'] > time.time() + 60:
        return cached['access_token']

    tenant_id = get_config('TENANT_ID')
    client_id = get_config('CLIENT_ID')
    client_secret = get_config('CLIENT_SECRET')
    if not all([tenant_id, client_id, client_secret]):
        raise RuntimeError('Missing TENANT_ID, CLIENT_ID, or CLIENT_SECRET in config')

    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    resp = requests.post(token_url, data={
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://api.loganalytics.io/.default',
        'grant_type': 'client_credentials',
    }, timeout=15)

    if not resp.ok:
        raise RuntimeError(f'Log Analytics token request failed: HTTP {resp.status_code}')

    data = resp.json()
    _token_cache['log_analytics'] = {
        'access_token': data['access_token'],
        'expires_at': time.time() + data.get('expires_in', 3600),
    }
    return data['access_token']


# ── Safety ──────────────────────────────────────────────────────────────────

_TAKE_PATTERN = re.compile(r'\b(take|top)\s+\d+', re.IGNORECASE)
MAX_QUERY_LENGTH = 5000


def _enforce_row_limit(query: str, default_limit: int = 500) -> str:
    """Append '| take N' if the query has no take/top clause."""
    if _TAKE_PATTERN.search(query):
        return query
    return query.rstrip().rstrip(';') + f'\n| take {default_limit}'


# ── Core ────────────────────────────────────────────────────────────────────

def run_kql(query: str, workspace_id: str | None = None) -> list[dict]:
    """Execute a KQL query against Log Analytics and return rows as dicts.

    Args:
        query: KQL query string (max 5000 chars).
        workspace_id: Override workspace; defaults to SENTINEL_WORKSPACE_ID config.

    Returns:
        List of dicts, one per row. Empty list if no results.

    Raises:
        RuntimeError: On config or API errors.
        ValueError: On invalid input.
    """
    if not query or not query.strip():
        raise ValueError('Query must not be empty')
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f'Query exceeds maximum length ({MAX_QUERY_LENGTH} chars)')

    ws = workspace_id or get_config('SENTINEL_WORKSPACE_ID')
    if not ws:
        raise RuntimeError('SENTINEL_WORKSPACE_ID not configured')

    safe_query = _enforce_row_limit(query)
    token = _get_log_analytics_token()
    url = f'{LOG_ANALYTICS_BASE}/workspaces/{ws}/query'
    headers = {'Authorization': f'Bearer {token}'}
    body = {'query': safe_query}

    resp = requests.post(url, headers=headers, json=body, timeout=60)

    if not resp.ok:
        # Extract detailed KQL error
        try:
            err_body = resp.json().get('error', {})
            parts = []
            if err_body.get('message'):
                parts.append(err_body['message'])
            inner = err_body.get('innererror', {})
            while inner:
                if inner.get('message'):
                    parts.append(inner['message'])
                inner = inner.get('innererror')
            msg = ' | '.join(parts) if parts else resp.text
        except Exception:
            msg = resp.text
        log.error('KQL %d — %s\nQuery:\n%s', resp.status_code, msg, safe_query)
        raise RuntimeError(f'KQL query failed ({resp.status_code}): {msg}')

    tables = resp.json().get('tables', [])
    if not tables:
        return []

    cols = [c['name'] for c in tables[0]['columns']]
    return [dict(zip(cols, row)) for row in tables[0]['rows']]
