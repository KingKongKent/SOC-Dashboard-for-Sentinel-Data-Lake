# SOC Dashboard for Microsoft Defender XDR

Automated Security Operations Center dashboard integrating **Microsoft Defender XDR**, **Microsoft Sentinel**, and **Threat Intelligence** feeds. Entra ID authentication, encrypted config management, SQLite persistence, and real-time incident actions (assign, escalate with email notification).

> **Built to inspire.** Created using AI-assisted (VIBE) coding to demonstrate SOC dashboard patterns. Use as a reference implementation — not validated for large-scale production.

## Quick Start (Local Development)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure credentials (copy template, fill in values)
cp .env.example .env
# Edit .env with your Azure credentials — NEVER commit .env

# 3. Verify secrets are excluded
git check-ignore .env          # should output: .env

# 4. Initialise database and fetch data
python fetch_live_data.py

# 5. Start the dashboard
python dashboard_backend.py

# 6. Open http://localhost:5000
```

### Optional: Automated Refresh
```bash
python hourly_refresh.py          # scheduler (every hour)
# or via Windows Task Scheduler:
powershell -File scripts/setup_task_scheduler.ps1
```

---

## Production Deployment (Ubuntu LXC)

### Prerequisites
- Ubuntu 24.04 LXC container
- Python 3.10+
- Microsoft Entra ID app registration with required permissions (see [Entra ID Setup](#entra-id-app-registration))
- DNS record pointing to your reverse proxy (not directly to the LXC)

### Automated Deployment

```bash
# 1. Copy files to the LXC
scp *.py *.html requirements.txt .env.example root@<LXC_IP>:/opt/soc-dashboard/
scp -r scripts static root@<LXC_IP>:/opt/soc-dashboard/

# 2. Run the deployment script
ssh root@<LXC_IP> 'bash /opt/soc-dashboard/scripts/deploy_lxc.sh'

# 3. Configure nginx domain and TLS
ssh root@<LXC_IP>
sed -i 's/YOUR_DOMAIN/your-actual-domain.com/g' /etc/nginx/sites-available/soc-dashboard
nginx -t && systemctl reload nginx
certbot --nginx -d your-actual-domain.com

# 4. Open https://your-actual-domain.com → the Setup Wizard will launch automatically
```

The deployment script (`scripts/deploy_lxc.sh`) will:
1. Install system packages (`python3`, `venv`, `nginx`, `certbot`)
2. Create a `socdash` service user (no login shell)
3. Set up `/opt/soc-dashboard` (app) and `/var/lib/soc-dashboard` (DB/data)
4. Create a Python venv with all dependencies + gunicorn
5. Initialize the SQLite database schema
6. Install systemd units (dashboard service + hourly refresh timer)
7. Configure and enable nginx reverse proxy

### First-Run Setup Wizard

On a fresh deployment, the dashboard automatically detects that Entra ID credentials are not configured and redirects all traffic to `/setup` — a built-in web-based setup wizard.

The setup wizard lets you:
- Enter **Tenant ID**, **Client ID**, and **Client Secret** from your Entra app registration
- **Test the connection** against Azure AD before saving
- Configure **Admin Users** (email addresses) and **Escalation Email**
- Set the **Redirect URI** (auto-detected from your browser URL)

Credentials are saved to the encrypted config database — no need to SSH in and edit `.env`. Once saved, the setup page locks itself and redirects to the normal login flow.

> **No `.env` editing required for first-time setup.** The `.env` file retains placeholder values; the setup wizard writes real credentials to the encrypted SQLite config, which takes precedence.

### What Gets Created

| Component | Path | Purpose |
|-----------|------|---------|
| App files | `/opt/soc-dashboard/` | Read-only application code |
| Database | `/var/lib/soc-dashboard/soc_dashboard.db` | SQLite database (writable) |
| Encryption key | `/var/lib/soc-dashboard/.encryption_key` | Fernet key for config secrets |
| Flask sessions | `/var/lib/soc-dashboard/flask_sessions/` | Session file storage |
| Credentials | `/opt/soc-dashboard/.env` | Environment vars (chmod 600) |
| Service | `dashboard.service` | gunicorn on 127.0.0.1:5000 (2 workers) |
| Timer | `hourly-refresh.timer` | Runs `append_data.py` every 1 hour |
| Nginx | `/etc/nginx/sites-available/soc-dashboard` | TLS reverse proxy |

### Critical Deployment Notes

**Database path:** The `DB_PATH` environment variable must be set in `.env` to `/var/lib/soc-dashboard/soc_dashboard.db`. If the systemd `WorkingDirectory` is wrong and `DB_PATH` is unset, a new empty DB gets created in the wrong location.

**Encryption key:** `config_manager.py` auto-generates a Fernet key on first run. **Never delete `.encryption_key`** — all encrypted settings in the DB become unreadable.

**`.env` permissions:** Must be `chmod 600`, owned by `socdash`. The deployment script sets this, but manual edits can reset permissions.

**Gunicorn (not Flask dev server):** Production must use gunicorn via `dashboard.service`. Flask's dev server is single-threaded and unsuitable.

**SQLite concurrency:** With multiple gunicorn workers writing simultaneously, you may see "database is locked" errors. Enable WAL mode if needed: `PRAGMA journal_mode=WAL`.

### TLS Certificate

```bash
# On the LXC, after DNS is configured:
certbot certonly --webroot -w /var/www/html -d your-domain.com
# Use RSA key type for maximum browser compatibility:
certbot certonly --key-type rsa --preferred-chain 'ISRG Root X1' -d your-domain.com
```

> ECDSA certs (Let's Encrypt E7, ISRG Root X2) may show "Not Secure" on some Windows machines. RSA certs (R12, ISRG Root X1) are universally trusted.

### Reverse Proxy Configuration

If traffic routes through an upstream proxy (SNI/stream routing), uncomment the proxy protocol lines in `scripts/nginx_site.conf`:

```nginx
listen 443 ssl http2 proxy_protocol;
set_real_ip_from <PROXY_IP>;
real_ip_header proxy_protocol;
```

**DNS must point to the proxy, not directly to the LXC.** Direct connections bypass the proxy protocol preamble and cause `ERR_CONNECTION_RESET`.

### Updating After Code Changes

```bash
# SCP changed files and restart
scp <changed_files> root@<LXC_IP>:/opt/soc-dashboard/
ssh root@<LXC_IP> 'systemctl restart dashboard'
```

---

## Entra ID App Registration

### Required Application Permissions

| API | Permission | Type | Purpose |
|-----|-----------|------|---------|
| Microsoft Graph | `SecurityIncident.Read.All` | Application | Fetch incidents |
| Microsoft Graph | `SecurityIncident.ReadWrite.All` | Application | Assign/escalate incidents |
| Microsoft Graph | `SecurityEvents.Read.All` | Application | Read security events / Secure Score |
| Microsoft Graph | `User.Read.All` | Application | User lookup |
| Microsoft Graph | `Mail.Send` | Application | Escalation email notifications |
| Microsoft Graph | `ThreatIntelligence.Read.All` | Application | MDTI articles *(optional — requires Defender TI license)* |

After adding permissions, **grant admin consent** — requires Global Administrator or Privileged Role Administrator.

### Redirect URI

Register in Entra: `https://<your-domain>/auth/callback`

Missing this causes `AADSTS50011` errors during login.

### Auth Flow

- **User login:** MSAL authorization code flow (interactive browser login)
- **API calls to Graph:** Client credentials flow (app-only token)
- **Admin detection:** `ADMIN_USERS` env var (comma-separated emails), not directory roles
- **Session:** Filesystem-based, 8-hour lifetime, `HttpOnly` + `SameSite=Lax` + `Secure` cookies

---

## Configuration

### `.env` Variables

```env
# Required — Entra ID App Registration
CLIENT_ID=your-app-client-id
CLIENT_SECRET=your-client-secret
TENANT_ID=your-tenant-id

# Required — Auth
SECRET_KEY=<random-hex-string>
REDIRECT_URI=https://your-domain.com/auth/callback
CORS_ORIGINS=https://your-domain.com
ADMIN_USERS=admin@yourdomain.com

# Optional — Sentinel
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_WORKSPACE_NAME=your-workspace-name

# Optional — Threat Intel API Keys
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Optional — Escalation
ESCALATION_EMAIL=soc-team@yourdomain.com

# Optional — Operational
REFRESH_INTERVAL_MINUTES=60
DB_PATH=/var/lib/soc-dashboard/soc_dashboard.db
CONFIG_KEY_PATH=/var/lib/soc-dashboard/.encryption_key
```

### Config Management

Settings can be managed in two ways:
1. **`.env` file** — read on startup
2. **Admin Settings UI** — stored encrypted in SQLite, takes precedence over `.env`

Secrets (`CLIENT_SECRET`, API keys) are Fernet-encrypted at rest in the database. The encryption key at `CONFIG_KEY_PATH` is generated on first run — **do not delete it**.

---

## API Endpoints

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/setup` | GET | — | First-run setup wizard (redirects to `/login` once configured) |
| `/api/setup` | POST | — | Save initial config (locked after setup completes) |
| `/api/setup/test-connection` | POST | — | Test Graph API credentials before saving |
| `/login` | GET | — | Initiates Entra ID OAuth2 flow |
| `/auth/callback` | GET | — | Entra redirect target (exchanges code for token) |
| `/logout` | GET | — | Clears session, redirects to `/login` |
| `/` | GET | `@require_login` | Serves the dashboard SPA |
| `/api/me` | GET | `@require_login` | Returns current user info |
| `/api/dashboard-data` | GET | `@require_login` | Incidents, alerts, metrics, secure score (supports `?days=`, `?severity=`, `?status=` filters) |
| `/api/database-stats` | GET | `@require_login` | Row counts and date ranges |
| `/api/incidents/<id>/assign` | POST | `@require_login` | Assigns incident in Defender XDR + local DB |
| `/api/incidents/<id>/escalate` | POST | `@require_login` | Bumps severity to High, adds tag + comment, sends email |
| `/api/settings` | GET | `@require_admin` | Returns all config (secrets masked) |
| `/api/settings` | PUT | `@require_admin` | Updates config values |
| `/api/settings/test-connection` | POST | `@require_admin` | Tests Graph API connectivity |
| `/api/refresh` | POST | `@require_admin` | Triggers immediate data refresh |

---

## Features

| Area | Detail |
|------|--------|
| **Authentication** | Entra ID OAuth2 with MSAL, admin role via email list |
| **Secure Score** | Live from Microsoft Graph API with category breakdown |
| **Incidents** | Timeline filtering (7d–90d), severity & status filters, hide-redirected toggle |
| **Incident Actions** | Assign to Me, Escalate (severity bump + email notification) — updates Defender XDR via Graph API |
| **Alerts** | Linked to incidents, product and detection source breakdown |
| **Threat Intel** | IOC extraction from incidents, VirusTotal, AbuseIPDB, MDTI articles |
| **Redirected Incidents** | Detected and labeled with target incident link; hidden by default to reduce noise |
| **Admin Settings** | Web UI for managing API keys, refresh interval, escalation email |
| **Encrypted Config** | Secrets stored with Fernet encryption in SQLite |
| **Auto-Refresh** | systemd timer (hourly) + configurable interval via settings |

## Project Structure

```
SOC-Dashboard/
├── dashboard_backend.py       # Flask API server + auth routes + security headers
├── database.py                # SQLite schema, CRUD, update helpers
├── fetch_live_data.py         # Graph API data fetchers + write helpers (assign, escalate, email)
├── auth.py                    # Entra ID MSAL login flow + @require_login / @require_admin
├── config_manager.py          # Encrypted config CRUD (DB → env fallback)
├── append_data.py             # Incremental data append logic
├── hourly_refresh.py          # Scheduler with timeout wrapper
├── soc-dashboard-live.html    # Single-page dashboard frontend (Chart.js, vanilla JS)
├── setup.html                 # First-run setup wizard (Entra ID credentials)
├── static/
│   └── favicon.svg            # Shield favicon
├── requirements.txt           # Python dependencies
├── .env.example               # Credential template (safe to commit)
├── scripts/
│   ├── deploy_lxc.sh          # Automated LXC deployment
│   ├── setup_systemd.sh       # systemd service + timer creation
│   ├── nginx_site.conf        # nginx reverse proxy template (with proxy_protocol support)
│   ├── pre_commit_check.py    # Pre-commit secret scanner
│   ├── setup_task_scheduler.ps1 # Windows Task Scheduler setup
│   └── backfill_redirect.py   # One-off: backfill redirectIncidentId data
├── docs/
│   ├── ARCHITECTURE.md        # System architecture & data flow
│   ├── INVENTORY.md           # File-by-file inventory
│   └── SECURITY_FIXES.md      # Tracked vulnerability patches
└── .github/
    └── copilot-instructions.md # Copilot coding conventions & pitfalls
```

## Security

- All credentials via `.env` + `python-dotenv` — **never hardcoded**
- Secrets encrypted at rest with Fernet in SQLite config table
- `.gitignore` blocks `.env`, `*.key`, `*.pem`, `*secret*`, `*.db`
- Pre-commit script scans for leaked secrets (`scripts/pre_commit_check.py`)
- CSP headers restrict script/style/font sources to `https://cdn.jsdelivr.net`
- All routes auth-protected (`@require_login` for users, `@require_admin` for settings)
- SQL queries use parameterized `?` placeholders — no f-strings in SQL
- `update_incident_field()` uses column whitelist — no arbitrary column updates
- See [docs/SECURITY_FIXES.md](docs/SECURITY_FIXES.md) for tracked patches

## Technologies

- **Frontend:** HTML5, CSS3, JavaScript, Chart.js 4.4.0
- **Backend:** Python 3.10+, Flask 3.1, Flask-CORS, Flask-Session
- **Auth:** MSAL 1.31 (Entra ID OAuth2 authorization code flow)
- **Database:** SQLite3 with JSON data blobs
- **Encryption:** cryptography (Fernet)
- **Production server:** gunicorn (2 workers, systemd managed)
- **Reverse proxy:** nginx with TLS (Let's Encrypt)
- **Scheduling:** systemd timer (production) / schedule library (development)
- **APIs:** Microsoft Graph Security, Defender XDR, VirusTotal, AbuseIPDB

## Future Enhancements

- [x] SQLite database for historical data
- [x] Timeline filtering (7/30/60/90/all days)
- [x] Hourly automated refresh
- [x] Real MTTD/MTTR calculations
- [x] Entity extraction and tracking
- [x] Entra ID authentication with admin roles
- [x] Encrypted settings management
- [x] Incident actions (assign, escalate with email)
- [x] Redirected incident detection and filtering
- [x] First-run web setup wizard (no SSH required for initial config)
- [ ] WebSocket live streaming for instant updates
- [ ] Multi-workspace support
- [ ] Export incident reports to PDF/Excel
- [ ] Custom KQL query builder
- [ ] Rate limiting on API endpoints

## License

MIT — see [LICENSE](LICENSE)
- [ ] Advanced correlation rules

## 📝 Development

```bash
# Start backend in debug mode (auto-reload enabled)
python dashboard_backend.py
# Server reloads automatically when Python files change

# Fetch fresh data while server is running
python fetch_live_data.py
python append_data.py

# Test date filtering
# Open http://localhost:5000 and click 7d, 30d, 60d, 90d, All buttons

# Check database stats
python -c "from database import get_database_stats; print(get_database_stats())"
```

## 🏗️ Architecture

```
┌─────────────────┐
│    Browser      │
│  (Dashboard)    │ ← Auto-refresh every 60 min
└────────┬────────┘
         │ HTTP GET with ?days=30
         ▼
┌─────────────────┐
│  Flask Server   │
│  (Port 5000)    │ ← API with date filtering
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ soc_dashboard.db│ ← SQLite with indexed queries
│  • 100 incidents│
│  • 316 alerts   │
│  • 191 entities │
└────────┬────────┘
         ▲
         │
┌────────┴────────┐
│ hourly_refresh  │ ← Runs every hour
│     .py         │
└────────┬────────┘
         │
         ├─► Microsoft Defender (MCP)
         ├─► Microsoft Sentinel (MCP)
         ├─► Microsoft Graph API
         └─► Threat Intel APIs (VT, Talos, AbuseIPDB)
```

## 🤝 Contributing

This is a live SOC dashboard project. Contributions welcome for:
- Additional threat intelligence sources
- Advanced KQL queries for Sentinel
- Custom visualization components
- Performance optimizations
- Security enhancements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses the following open-source dependencies:

| Package | License | Compatible |
|---------|---------|------------|
| Flask | BSD-3-Clause | ✅ Yes |
| Werkzeug | BSD-3-Clause | ✅ Yes |
| Jinja2 | BSD-3-Clause | ✅ Yes |
| Flask-CORS | MIT | ✅ Yes |
| Requests | Apache 2.0 | ✅ Yes |
| python-dotenv | BSD-3-Clause | ✅ Yes |
| schedule | MIT | ✅ Yes |
| msal | MIT | ✅ Yes |
| certifi | MPL-2.0 | ✅ Yes |
| urllib3 | MIT | ✅ Yes |
| Chart.js | MIT | ✅ Yes |

**All dependencies use permissive open-source licenses compatible with commercial and non-commercial use.**

### Microsoft API Usage

This dashboard integrates with Microsoft services:
- **Microsoft Defender** - Requires valid Microsoft 365 E5 or Defender subscription
- **Microsoft Sentinel** - Requires Azure subscription and Sentinel workspace
- **Microsoft Graph API** - Covered under Microsoft API Terms of Use
- **Microsoft Entra ID** - Requires valid Azure AD/Entra ID tenant

**Note:** Access to Microsoft APIs requires proper licensing from Microsoft. This project does not provide or include any Microsoft licenses.

### External Threat Intelligence APIs

Optional integrations with third-party services:
- **VirusTotal** - Free tier available, API key required
- **AbuseIPDB** - Free tier available, API key required  
- **Cisco Talos** - May require enterprise license

Check each service's terms of use and licensing requirements separately.

## ⚖️ Disclaimer

This software is provided "as is" without warranty. Users are responsible for:
- Obtaining necessary Microsoft licenses and subscriptions
- Complying with Microsoft API terms of service
- Ensuring proper security and access controls
- Meeting regulatory and compliance requirements
- Obtaining API keys and licenses for third-party services

The authors assume no liability for misuse or unauthorized access to security data.
