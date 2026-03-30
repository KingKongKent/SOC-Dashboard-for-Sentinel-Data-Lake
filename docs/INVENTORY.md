# File Inventory — SOC Dashboard

> Last updated: 2026-03-30

## Source Files

| File | Purpose | Key Dependencies |
|------|---------|-----------------|
| `dashboard_backend.py` | Flask API server. Serves dashboard data, auth routes, settings API. Protected by Entra ID login. Includes CSP + security headers. | flask, flask-cors, flask-session, database.py, fetch_live_data.py, auth.py, config_manager.py |
| `database.py` | SQLite schema definition, table creation, CRUD helpers for incidents/alerts/entities/threat-intel/metrics/config. Parameterised queries throughout. | sqlite3 (stdlib) |
| `fetch_live_data.py` | Data fetchers: Microsoft Graph Security API (incidents, Secure Score, MDTI), Sentinel KQL (Log Analytics REST API), VirusTotal, AbuseIPDB, Talos. Three-tier fallback: Graph → Sentinel → Demo. | requests, msal, python-dotenv, config_manager.py |
| `append_data.py` | Incremental data loader — fetches new incidents/alerts and inserts only those not already in DB. | database.py, fetch_live_data.py |
| `hourly_refresh.py` | Long-running scheduler with configurable interval from DB settings. Includes 5-min timeout per fetch cycle. | schedule, concurrent.futures, append_data.py, config_manager.py |
| `auth.py` | Entra ID OAuth2 authorization code flow (multi-tenant). Login, callback, logout, `@require_login` and `@require_admin` decorators. | msal, flask |
| `config_manager.py` | Encrypted configuration CRUD. DB→env fallback for all settings. Fernet encryption for secrets. | cryptography, database.py |
| `soc-dashboard-live.html` | Single-page frontend — KPI cards, charts (Chart.js), incident table, timeline filters. Auth-gated with Entra ID login redirect. Admin settings overlay. Data source badge (Graph/Sentinel/Demo). | Chart.js 4.4 (CDN) |
| `setup.html` | First-run setup wizard. Presented when Entra ID credentials are missing/placeholder. Saves config to encrypted DB via `/api/setup`. Self-disables after setup completes. | — (standalone HTML) |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `scripts/pre_commit_check.py` | Pre-commit scanner for leaked secrets and common vulns |
| `scripts/deploy_lxc.sh` | Automated deployment to Ubuntu 24.04 LXC with env var validation |
| `scripts/setup_systemd.sh` | Creates systemd units: dashboard.service + hourly-refresh.timer |
| `scripts/nginx_site.conf` | nginx reverse proxy config template (replace `YOUR_DOMAIN` before use) |
| `scripts/setup_task_scheduler.ps1` | Creates a Windows Scheduled Task for hourly refresh |
| `scripts/start_hourly_refresh.bat` | Simple batch launcher for `hourly_refresh.py` (Windows) |

## Configuration

| File | Purpose |
|------|---------|
| `.env.example` | Template for required environment variables (safe to commit) |
| `.gitignore` | Security-hardened ignore rules — blocks `.env`, `*.db`, `*.key`, `*secret*` |
| `requirements.txt` | Pinned Python dependencies |

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | Quick start, feature summary, project structure, production deployment guide |
| `docs/ARCHITECTURE.md` | Component diagram, data flow, DB schema, tech stack, deployment topology |
| `docs/INVENTORY.md` | This file — file-by-file inventory |
| `docs/SECURITY_FIXES.md` | Tracked vulnerability discoveries and patches (8 entries) |
| `SECURITY.md` | GitHub security policy (vulnerability reporting) |
| `LICENSE` | MIT License |

## Static Assets

| File | Purpose |
|------|---------|
| `static/favicon.svg` | Shield favicon (SVG, served via Flask route) |

## Copilot / Agent Files

| File | Purpose |
|------|---------|
| `.github/copilot-instructions.md` | Coding conventions, security rules, pitfalls for Copilot agents |
| `skills/soc-dashboard-deployment/SKILL.md` | Copilot skill: LXC deployment, systemd, nginx, TLS, DNS, known pitfalls |

## Runtime Artifacts (gitignored)

| File | Created By | Purpose |
|------|-----------|---------|
| `.env` | User | Real credentials |
| `soc_dashboard.db` | `database.py` | SQLite database |
| `dashboard_data.json` | `fetch_live_data.py` | JSON fallback data |
| `*.log` | Various | Log output |

## External API Dependencies

| API | Used By | Auth Method | Required Permission |
|-----|---------|-------------|-------------------|
| Microsoft Graph `/security/incidents` | fetch_live_data.py | OAuth2 client_credentials | SecurityIncident.Read.All |
| Microsoft Graph `/security/secureScores` | fetch_live_data.py | OAuth2 client_credentials | SecurityEvents.Read.All |
| Microsoft Graph `/security/threatIntelligence/articles` | fetch_live_data.py | OAuth2 client_credentials | ThreatIntelligence.Read.All |
| Microsoft Sentinel (Log Analytics REST API) | fetch_live_data.py | OAuth2 client_credentials | Log Analytics Reader |
| Microsoft Defender XDR (incidents/alerts) | fetch_live_data.py | OAuth2 (Graph fallback) | SecurityIncident.Read.All |
| VirusTotal `/api/v3/files` | fetch_live_data.py | API key header | VirusTotal API key |
| AbuseIPDB | fetch_live_data.py | Derived from incidents | — |
| Cisco Talos | fetch_live_data.py | Derived from incidents | — |
