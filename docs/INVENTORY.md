# File Inventory — SOC Dashboard

> Last updated: 2025-07-28

## Source Files

| File | Purpose | Key Dependencies |
|------|---------|-----------------|
| `dashboard_backend.py` | Flask API server. Serves dashboard data, auth routes, settings API. Protected by Entra ID login. Includes CSP + security headers. | flask, flask-cors, flask-session, database.py, fetch_live_data.py, auth.py, config_manager.py |
| `database.py` | SQLite schema definition, table creation, CRUD helpers for incidents/alerts/entities/threat-intel/metrics/config. Parameterised queries throughout. | sqlite3 (stdlib) |
| `fetch_live_data.py` | Data fetchers: Microsoft Graph Security API (incidents, Secure Score, MDTI), Sentinel KQL (Log Analytics REST API), VirusTotal, AbuseIPDB, Talos. Two-tier fallback: Graph → Sentinel (returns empty when no credentials). Includes `graph_post_comment()` for posting enrichment results as incident comments (max 1000 chars). | requests, msal, python-dotenv, config_manager.py |
| `append_data.py` | Incremental data loader — fetches new incidents/alerts and inserts only those not already in DB. | database.py, fetch_live_data.py |
| `hourly_refresh.py` | Long-running scheduler with configurable interval from DB settings. Includes 5-min timeout per fetch cycle. | schedule, concurrent.futures, append_data.py, config_manager.py |
| `auth.py` | Entra ID OAuth2 authorization code flow (multi-tenant). Login, callback, logout, `@require_login` and `@require_admin` decorators. | msal, flask |
| `config_manager.py` | Encrypted configuration CRUD. DB→env fallback for all settings. Fernet encryption for secrets. | cryptography, database.py |
| `ioc_upload.py` | IOC upload engine — uploads threat intelligence indicators to Sentinel via REST API. Supports single IOC, bulk CSV, and open-source feed ingestion with deduplication. Auto-discovers workspace/resource-group via Resource Graph. | requests, config_manager.py, database.py |
| `ai_assistant.py` | Azure AI Foundry integration — agent mode with Sentinel MCP tools (data-exploration + triage), direct completion fallback. Caches attack stories. | openai, azure-identity, config_manager.py |
| `security_copilot.py` | Security Copilot enrichment module — prompt construction, response parsing, on-demand enrichment via Foundry agent, Logic App webhook processing, auto-enrich batch helper. Results cached 1 hour. Enrichment posted as Sentinel comment (≤1000 chars). | ai_assistant.py, database.py, config_manager.py |
| `sentinel_kql.py` | KQL query engine — runs ad-hoc KQL queries against Log Analytics REST API with safety limits (row cap, timeout). | requests, config_manager.py |
| `soc-dashboard-live.html` | Single-page frontend — KPI cards, charts (Chart.js), incident table, timeline filters, IOC upload tab, light/dark theme toggle. Auth-gated with Entra ID login redirect. Admin settings overlay. | Chart.js 4.4 (CDN) |
| `setup.html` | First-run setup wizard. Presented when Entra ID credentials are missing/placeholder. Saves config to encrypted DB via `/api/setup`. Self-disables after setup completes. | — (standalone HTML) |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `scripts/pre_commit_check.py` | Pre-commit scanner for leaked secrets and common vulns |
| `scripts/generate_demo_data.py` | Standalone demo data generator. Writes `dashboard_data.json` with synthetic incidents, alerts, Secure Score. Optional `--db` flag inserts into SQLite. |
| `scripts/deploy_lxc.sh` | Automated FHS-compliant deployment to Ubuntu 24.04 LXC. Auto-generates self-signed TLS if no Let's Encrypt cert. Merges new `.env.example` keys into existing `.env`. Auto-detects `server_name` from `REDIRECT_URI`. Includes health checks. |
| `scripts/setup_systemd.sh` | Creates systemd units: dashboard.service + hourly-refresh.timer (FHS paths) |
| `scripts/nginx_site.conf` | nginx reverse proxy config template (replace `YOUR_DOMAIN` before use) |

> Retired scripts (one-off migrations, debug helpers, Windows-only launchers) are in `_archive/` (gitignored).

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
| `docs/AI_SETUP.md` | How to configure Azure AI Foundry / OpenAI integration (agent mode, direct completion, MCP tools) |
| `docs/SECURITY_FIXES.md` | Tracked vulnerability discoveries and patches (14 entries) |
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
| Microsoft Graph `/security/incidents/{id}/comments` | fetch_live_data.py | OAuth2 client_credentials | SecurityIncident.ReadWrite.All |
| Microsoft Graph `/security/secureScores` | fetch_live_data.py | OAuth2 client_credentials | SecurityEvents.Read.All |
| Microsoft Graph `/security/threatIntelligence/articles` | fetch_live_data.py | OAuth2 client_credentials | ThreatIntelligence.Read.All |
| Microsoft Sentinel (Log Analytics REST API) | fetch_live_data.py | OAuth2 client_credentials | Log Analytics Reader |
| Microsoft Defender XDR (incidents/alerts) | fetch_live_data.py | OAuth2 (Graph fallback) | SecurityIncident.Read.All |
| Microsoft Sentinel (Threat Intelligence) | ioc_upload.py | OAuth2 client_credentials | Microsoft.Sentinel (Contributor or TI Contributor) |
| Azure Resource Graph | ioc_upload.py | OAuth2 client_credentials | Reader |
| Azure AI Foundry (OpenAI) | ai_assistant.py | Entra SP (client_credentials) | Cognitive Services OpenAI User |
| VirusTotal `/api/v3/files` | fetch_live_data.py | API key header | VirusTotal API key |
| Microsoft Sentinel TI (ARM REST API) | ioc_upload.py | OAuth2 client_credentials | Microsoft Sentinel Contributor |
| AbuseIPDB | fetch_live_data.py | Derived from incidents | — |
| Cisco Talos | fetch_live_data.py | Derived from incidents | — |
