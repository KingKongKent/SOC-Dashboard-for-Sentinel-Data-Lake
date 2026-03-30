"""
Entra ID Authentication for SOC Dashboard
Uses MSAL (authorization code flow) for interactive user login.
"""

import os
import functools
from flask import session, redirect, url_for, request, jsonify
import msal
from dotenv import load_dotenv

load_dotenv()


def _cfg(key: str, default: str = '') -> str:
    """Read config, preferring config_manager DB values when available."""
    try:
        from config_manager import get_config
        val = get_config(key)
        if val:
            return val
    except Exception:
        pass
    return os.getenv(key, default).strip()


SCOPES = ['User.Read']


def _get_authority() -> str:
    """Use tenant-specific authority if TENANT_ID is set, otherwise /common."""
    tenant = _cfg('TENANT_ID')
    if tenant:
        return f'https://login.microsoftonline.com/{tenant}'
    return 'https://login.microsoftonline.com/common'


def _get_msal_app():
    """Build a ConfidentialClientApplication using current config."""
    client_id = _cfg('CLIENT_ID')
    client_secret = _cfg('CLIENT_SECRET')
    if not client_id or not client_secret:
        return None
    return msal.ConfidentialClientApplication(
        client_id,
        authority=_get_authority(),
        client_credential=client_secret,
    )


def _get_redirect_uri() -> str:
    return _cfg('REDIRECT_URI', 'http://localhost:5000/auth/callback')


def _is_admin_user(email: str) -> bool:
    """Check if the user's email is in the ADMIN_USERS list."""
    admin_csv = _cfg('ADMIN_USERS', '')
    if not admin_csv:
        return False
    admin_emails = {e.strip().lower() for e in admin_csv.split(',') if e.strip()}
    return email.lower() in admin_emails


# ── Decorators ──────────────────────────────────

def require_login(f):
    """Redirect browser requests to /login; return 401 for API calls."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('user'):
            return f(*args, **kwargs)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        return redirect(url_for('login'))
    return wrapper


def require_admin(f):
    """Require the user to be listed in ADMIN_USERS."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = session.get('user')
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        if not user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return wrapper


# ── Route handlers (called from dashboard_backend) ──

def initiate_login():
    """Start the OAuth2 authorization code flow."""
    app = _get_msal_app()
    if not app:
        return '<h3>Login unavailable</h3><p>CLIENT_ID and CLIENT_SECRET must be configured.</p>', 503

    flow = app.initiate_auth_code_flow(
        scopes=SCOPES,
        redirect_uri=_get_redirect_uri(),
    )
    session['auth_flow'] = flow
    return redirect(flow['auth_uri'])


def handle_callback():
    """Exchange the authorization code for tokens and populate session."""
    flow = session.pop('auth_flow', None)
    if not flow:
        return redirect(url_for('login'))

    app = _get_msal_app()
    if not app:
        return redirect(url_for('login'))

    result = app.acquire_token_by_auth_code_flow(
        flow,
        dict(request.args),
    )

    if 'error' in result:
        return (
            f"<h3>Login failed</h3>"
            f"<p>{result.get('error_description', result['error'])}</p>"
            f"<a href='/login'>Try again</a>"
        ), 400

    id_claims = result.get('id_token_claims', {})
    email = id_claims.get('preferred_username', '')
    is_admin = _is_admin_user(email)
    print(f"  🔑 User {email} — is_admin: {is_admin}")
    session['user'] = {
        'name': id_claims.get('name', 'Unknown'),
        'email': email,
        'oid': id_claims.get('oid', ''),
        'is_admin': is_admin,
        'tid': id_claims.get('tid', ''),
    }
    return redirect('/')


def handle_logout():
    """Clear the local session and redirect to login."""
    session.clear()
    return redirect('/login')


def get_current_user():
    """Return the current user info from session (for /api/me)."""
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({
        'name': user['name'],
        'email': user['email'],
        'is_admin': user.get('is_admin', False),
    })
