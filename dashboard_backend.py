"""
SOC Dashboard Backend - Serves data from SQLite database with timeline filtering
"""
from flask import Flask, jsonify, redirect, send_file, send_from_directory, request, session
from flask_cors import CORS
from flask_session import Session
from datetime import datetime, timedelta
import json
import os
import secrets

# Import database functions
try:
    from database import (
        get_incidents,
        get_alerts,
        get_metrics_summary,
        get_latest_threat_intel,
        get_database_stats,
        init_database,
        update_incident_field,
    )
    from fetch_live_data import (
        fetch_secure_score, calculate_daily_alert_volume, get_last_incident_source,
        graph_patch_incident, graph_post_comment, graph_send_mail,
    )
    DB_AVAILABLE = True
except ImportError:
    print("⚠️  Database module not available, falling back to JSON mode")
    DB_AVAILABLE = False


def _detect_incident_source(incidents: list) -> str:
    """Detect data source from incident characteristics.
    Graph incidents have numeric IDs; Sentinel have GUIDs; demo have 'INC-' prefix."""
    if not incidents:
        return 'unknown'
    sample_id = str(incidents[0].get('id', ''))
    if sample_id.isdigit():
        return 'microsoft_graph_api'
    if sample_id.startswith('INC-') or sample_id.startswith('DEMO'):
        return 'demo'
    return 'sentinel_kql'

from auth import (
    require_login,
    require_admin,
    initiate_login,
    handle_callback,
    handle_logout,
    get_current_user,
)
from config_manager import get_config, set_config, get_all_config

# ── First-run setup detection ───────────────────

_PLACEHOLDER_PATTERNS = ('your-', 'change-me', 'yourdomain', 'placeholder')

def _needs_setup() -> bool:
    """True when essential Entra ID config is missing or still has placeholder values."""
    for key in ('TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET'):
        val = get_config(key) or ''
        if not val or any(p in val.lower() for p in _PLACEHOLDER_PATTERNS):
            return True
    return False

app = Flask(__name__)

# Session config
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(
    os.getenv('DB_PATH', 'soc_dashboard.db').rsplit(os.sep, 1)[0] or '.',
    'flask_sessions',
)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') != 'development'
Session(app)

cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000')
CORS(app, origins=[o.strip() for o in cors_origins.split(',')])

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "form-action 'self' https://login.microsoftonline.com"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.svg', mimetype='image/svg+xml')

# ── First-run setup routes ──────────────────────

_SETUP_PATHS = frozenset({'/setup', '/api/setup', '/api/setup/test-connection', '/favicon.ico'})

@app.before_request
def _check_setup_needed():
    """Redirect everything to the setup page until Entra creds are configured."""
    if request.path in _SETUP_PATHS:
        return None
    if _needs_setup():
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Initial setup required', 'setup_url': '/setup'}), 503
        return redirect('/setup')
    return None


@app.route('/setup')
def setup_page():
    """Serve the first-run setup wizard."""
    if not _needs_setup():
        return redirect('/login')
    return send_file('setup.html')


@app.route('/api/setup', methods=['POST'])
def save_setup():
    """Save initial configuration (only works while setup is needed)."""
    if not _needs_setup():
        return jsonify({'error': 'Setup already complete'}), 403
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400
    SETUP_KEYS = {
        'TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET',
        'REDIRECT_URI', 'ADMIN_USERS', 'ESCALATION_EMAIL',
    }
    saved = []
    for key, value in payload.items():
        if key in SETUP_KEYS and isinstance(value, str) and value.strip():
            set_config(key, value.strip())
            saved.append(key)
    print(f'\u2699\ufe0f  Setup: saved {saved}')
    return jsonify({'success': True, 'saved': saved})


@app.route('/api/setup/test-connection', methods=['POST'])
def setup_test_connection():
    """Test Graph API connectivity with credentials from the request body (pre-save)."""
    if not _needs_setup():
        return jsonify({'error': 'Setup already complete'}), 403
    payload = request.get_json(silent=True) or {}
    client_id = (payload.get('CLIENT_ID') or '').strip()
    client_secret = (payload.get('CLIENT_SECRET') or '').strip()
    tenant_id = (payload.get('TENANT_ID') or '').strip()
    if not all([client_id, client_secret, tenant_id]):
        return jsonify({'success': False, 'message': 'Tenant ID, Client ID, and Client Secret are required.'})
    try:
        import requests as http
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        resp = http.post(token_url, data={
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials',
        }, timeout=10)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Connection successful \u2014 Graph API token acquired.'})
        err = resp.json().get('error_description', f'HTTP {resp.status_code}')
        return jsonify({'success': False, 'message': f'Token request failed: {err}'})
    except Exception:
        return jsonify({'success': False, 'message': 'Connection failed \u2014 check network and credentials.'})


# ── Auth routes (unauthenticated) ────────────────

@app.route('/login')
def login():
    return initiate_login()

@app.route('/auth/callback')
def auth_callback():
    return handle_callback()

@app.route('/logout')
def logout():
    return handle_logout()

@app.route('/api/me')
@require_login
def me():
    return get_current_user()

# ── Settings API (admin-only) ───────────────────

@app.route('/api/settings', methods=['GET'])
@require_admin
def get_settings():
    """Return all configurable settings (secrets masked)."""
    items = get_all_config()
    flat = {item['key']: item['value'] for item in items}
    return jsonify(flat)

@app.route('/api/settings', methods=['PUT'])
@require_admin
def update_settings():
    """Update one or more settings. Expects flat {key: value} JSON."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({'error': 'Missing JSON payload'}), 400

    ALLOWED = {
        'CLIENT_ID', 'CLIENT_SECRET', 'TENANT_ID',
        'SENTINEL_WORKSPACE_ID', 'SENTINEL_WORKSPACE_NAME',
        'VIRUSTOTAL_API_KEY', 'TALOS_API_KEY', 'ABUSEIPDB_API_KEY',
        'REFRESH_INTERVAL_MINUTES', 'ESCALATION_EMAIL',
    }
    updated = []
    for key, value in payload.items():
        if key not in ALLOWED:
            continue
        if value == '••••••••':
            continue
        set_config(key, str(value))
        updated.append(key)

    return jsonify({'updated': updated})

@app.route('/api/settings/test-connection', methods=['POST'])
@require_admin
def test_connection():
    """Test Graph API connectivity with current config."""
    try:
        import requests as http
        from config_manager import get_config as cfg
        client_id = cfg('CLIENT_ID')
        client_secret = cfg('CLIENT_SECRET')
        tenant_id = cfg('TENANT_ID')
        if not all([client_id, client_secret, tenant_id]):
            return jsonify({'success': False, 'message': 'Missing CLIENT_ID, CLIENT_SECRET, or TENANT_ID'})
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        resp = http.post(token_url, data={
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials',
        }, timeout=10)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Graph API connection successful'})
        return jsonify({'success': False, 'message': f'Token request failed: HTTP {resp.status_code}'})
    except Exception:
        return jsonify({'success': False, 'message': 'Connection test failed — check network and credentials'})

@app.route('/api/refresh', methods=['POST'])
@require_admin
def trigger_refresh():
    """Trigger an immediate data refresh."""
    try:
        from append_data import fetch_and_append_new_data
        result = fetch_and_append_new_data()
        return jsonify({'success': True, 'result': result})
    except Exception:
        return jsonify({'success': False, 'message': 'Refresh failed — check server logs'}), 500

# ── Dashboard routes (authenticated) ────────────

@app.route('/api/dashboard-data', methods=['GET'])
@require_login
def get_dashboard_data():
    """
    Serve dashboard data from SQLite database with filtering
    
    Query Parameters:
        days: Get data from last N days (e.g., ?days=7)
        start_date: ISO format start date (e.g., ?start_date=2026-01-01)
        end_date: ISO format end date (e.g., ?end_date=2026-02-03)
        severity: Filter by severity (e.g., ?severity=High)
        status: Filter by status (e.g., ?status=Active)
    """
    
    # Use database if available, otherwise fall back to JSON
    if DB_AVAILABLE:
        return get_dashboard_data_from_db()
    else:
        return get_dashboard_data_from_json()

def get_dashboard_data_from_db():
    """Get dashboard data from SQLite database with filtering"""
    try:
        # Get query parameters
        days = request.args.get('days', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        # Default to last 30 days if no filter specified
        if not any([days, start_date, end_date]):
            days = 30
        
        print(f"\n📊 Querying database with filters:")
        if days:
            print(f"   • Last {days} days")
        if start_date:
            print(f"   • Start date: {start_date}")
        if end_date:
            print(f"   • End date: {end_date}")
        if severity:
            print(f"   • Severity: {severity}")
        if status:
            print(f"   • Status: {status}")
        
        # Query incidents
        incidents = get_incidents(
            days=days,
            start_date=start_date,
            end_date=end_date,
            severity=severity,
            status=status
        )
        
        # Get alerts for the filtered incidents
        incident_ids = [inc.get('id') for inc in incidents]
        alerts = get_alerts(days=days, start_date=start_date, end_date=end_date)
        
        # Filter alerts to only those related to our incidents
        alerts = [a for a in alerts if a.get('incidentId') in incident_ids]
        
        # Get metrics for the filtered period
        metrics_days = days if days else 30
        metrics = get_metrics_summary(days=metrics_days)
        
        # Get latest threat intelligence
        threat_intel_data = get_latest_threat_intel()
        threat_intel = threat_intel_data.get('data', {}) if threat_intel_data else {}
        
        # Get secure score (always latest)
        secure_score_data = fetch_secure_score()
        
        # Calculate daily alert volume
        daily_alerts = calculate_daily_alert_volume(alerts)
        
        # Build response
        refresh_interval = int(get_config('REFRESH_INTERVAL_MINUTES', '60') or '60')
        data = {
            'timestamp': datetime.now().isoformat(),
            'dataSource': 'sqlite_database',
            'refreshInterval': refresh_interval,
            'filters': {
                'days': days,
                'start_date': start_date,
                'end_date': end_date,
                'severity': severity,
                'status': status
            },
            'secureScore': {
                'current': secure_score_data.get('percentage', 78.4),
                'max': 100,
                'trend': 5.2,
                'isDemo': secure_score_data.get('source') != 'microsoft_graph_api',
                'rawScore': secure_score_data.get('currentScore'),
                'maxPossible': secure_score_data.get('maxScore'),
                'controlScores': secure_score_data.get('controlScores', []),
                'categoryScores': secure_score_data.get('categoryScores', []),
                'recommendations': secure_score_data.get('recommendations', [])
            },
            'incidents': incidents,
            'alerts': alerts,
            'metrics': metrics,
            'incidentSource': _detect_incident_source(incidents),
            'secureScoreTrend': [],
            'dailyAlerts': daily_alerts,
            'threatIntelligence': threat_intel
        }
        
        print(f"✅ Serving {len(incidents)} incidents and {len(alerts)} alerts from database")
        return jsonify(data)
        
    except Exception as e:
        print(f"❌ Error querying database: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Database query failed',
            'message': 'An internal error occurred. Check server logs for details.'
        }), 500

def get_dashboard_data_from_json():
    """Fallback: Get dashboard data from JSON file"""
    try:
        data_file = 'dashboard_data.json'
        
        # Check if data file exists
        if not os.path.exists(data_file):
            return jsonify({
                'error': 'Dashboard data not found',
                'message': 'Please run "python migrate_json_to_db.py" to set up the database'
            }), 404
        
        # Read the pre-fetched data
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        data['dataSource'] = 'json_file'
        print(f"✅ Serving dashboard data from {data_file} (fallback mode)")
        print(f"   📊 Last updated: {data.get('timestamp')}")
        print(f"   📊 {len(data.get('incidents', []))} incidents, {len(data.get('alerts', []))} alerts")
        print(f"   📊 Secure Score: {data.get('secureScore', {}).get('current')}%")
        
        return jsonify(data)
        
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error in dashboard_data.json: {e}")
        return jsonify({
            'error': 'Invalid data file',
            'message': 'Failed to parse data file. Check server logs for details.'
        }), 500
    except Exception as e:
        print(f"❌ Error serving dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Server error',
            'message': 'An internal error occurred. Check server logs for details.'
        }), 500

@app.route('/api/database-stats', methods=['GET'])
@require_login
def get_db_stats():
    """Get database statistics"""
    if not DB_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        stats = get_database_stats()
        return jsonify(stats)
    except Exception as e:
        print(f"❌ Database stats error: {e}")
        return jsonify({'error': 'Failed to retrieve database statistics'}), 500

# ── Incident action routes (authenticated) ─────

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_login
def assign_incident(incident_id):
    """Assign a Graph Security incident to the logged-in user."""
    user = session.get('user', {})
    email = user.get('email', '')
    name = user.get('name', email)
    oid = user.get('oid', '')
    if not email:
        return jsonify({'error': 'No user email in session'}), 400
    if not str(incident_id).isdigit():
        return jsonify({'error': 'Only Graph incidents (numeric ID) can be assigned'}), 400
    try:
        graph_patch_incident(incident_id, {'assignedTo': email})
        graph_post_comment(incident_id,
                           f'Assigned to {name} ({email}) via SOC Dashboard')
        update_incident_field(incident_id, 'assigned_to', email)
        print(f'📌 Incident {incident_id} assigned to {email}')
        return jsonify({'success': True, 'assignedTo': email})
    except Exception as exc:
        print(f'❌ Assign incident {incident_id} failed: {exc}')
        return jsonify({'error': 'Failed to assign incident'}), 502


@app.route('/api/incidents/<incident_id>/escalate', methods=['POST'])
@require_login
def escalate_incident(incident_id):
    """Escalate: bump severity to High, tag, comment, email notification."""
    user = session.get('user', {})
    email = user.get('email', '')
    name = user.get('name', email)
    oid = user.get('oid', '')
    if not str(incident_id).isdigit():
        return jsonify({'error': 'Only Graph incidents (numeric ID) can be escalated'}), 400

    body = request.get_json(silent=True) or {}
    reason = body.get('reason', 'No reason provided')

    try:
        # 1. Bump severity + tag
        graph_patch_incident(incident_id, {
            'severity': 'high',
            'customTags': ['Escalated'],
        })
        # 2. Comment
        graph_post_comment(incident_id,
            f'ESCALATED by {name} ({email}) via SOC Dashboard. Reason: {reason}')
        # 3. Update local DB
        update_incident_field(incident_id, 'severity', 'High')

        # 4. Send email notification
        escalation_email = get_config('ESCALATION_EMAIL') or ''
        recipients = [r.strip() for r in escalation_email.split(',') if r.strip()]
        if recipients and oid:
            subject = f'[SOC] Incident {incident_id} Escalated'
            html_body = (
                f'<h2>Incident {incident_id} Escalated</h2>'
                f'<p><b>Escalated by:</b> {name} ({email})</p>'
                f'<p><b>Reason:</b> {reason}</p>'
                f'<p><a href="https://security.microsoft.com/incidents/{incident_id}">'
                f'Open in Defender Portal</a></p>'
            )
            try:
                graph_send_mail(oid, subject, html_body, recipients)
                print(f'📧 Escalation email sent to {recipients}')
            except Exception as mail_exc:
                print(f'⚠️  Escalation email failed: {mail_exc}')

        print(f'⚠️  Incident {incident_id} escalated by {email}')
        return jsonify({'success': True})
    except Exception as exc:
        print(f'❌ Escalate incident {incident_id} failed: {exc}')
        return jsonify({'error': 'Failed to escalate incident'}), 502


@app.route('/')
@require_login
def serve_dashboard():
    """Serve the dashboard HTML"""
    return send_file('soc-dashboard-live.html')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting SOC Dashboard Backend Server")
    print("="*60)
    
    if DB_AVAILABLE:
        print("✅ Database mode: SQLite with timeline filtering")
        try:
            stats = get_database_stats()
            print(f"📊 Database contains:")
            print(f"   • {stats['incidents']} incidents")
            print(f"   • {stats['alerts']} alerts")
            print(f"   • {stats['entities']} entities")
            print(f"   • Date range: {stats['oldest_incident']} to {stats['newest_incident']}")
        except:
            print("⚠️  Database exists but may be empty. Run: python migrate_json_to_db.py")
    else:
        print("⚠️  JSON fallback mode (database not available)")
    
    print("\n💡 API Endpoints:")
    print("   • GET /api/dashboard-data (supports filtering)")
    print("   • GET /api/dashboard-data?days=7 (last 7 days)")
    print("   • GET /api/dashboard-data?days=30 (last 30 days)")
    print("   • GET /api/dashboard-data?severity=High")
    print("   • GET /api/database-stats")
    print("\n🌐 Dashboard: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', '5000')),
        debug=os.getenv('FLASK_DEBUG', '0') == '1'
    )
