# SOC Dashboard — Copilot Instructions & Pitfalls

## Project Context

This is a Python/Flask SOC Dashboard that integrates with Microsoft Sentinel Data Lake,
Defender XDR, and third-party threat intel APIs. SQLite backend, single-page HTML frontend.

## Security Rules (MANDATORY)

1. **Never hardcode secrets.** All credentials must come from `config_manager.get_config()` → `os.getenv()` fallback.
2. **Never commit `.env`** — it is gitignored. Use `.env.example` for templates.
3. **Always use parameterised queries** for SQLite — no f-strings or `.format()` in SQL.
4. **Flask `debug=True` is forbidden** in committed code. Use `FLASK_DEBUG` env var.
5. **Do not bind to `0.0.0.0`** by default. Use `127.0.0.1` unless overridden by env var.
6. **CORS must be restricted** — never use `CORS(app)` with no origins parameter.
7. **Do not return `str(e)`** in API responses — log the error, return a generic message.
8. **Run `scripts/pre_commit_check.py`** before every commit to scan for leaked secrets.
9. **Before committing:** `git diff --cached | Select-String "token|secret|password|api.key"` to verify.
10. **All routes must be auth-protected** — use `@require_login` for user routes, `@require_admin` for settings routes.

## Known Pitfalls

### Python / Flask
- `database.py` uses `LIMIT` in queries — always pass it as a parameterised `?`, never f-string.
- Flask's `send_from_directory` needs `safe_join` awareness — never join user input to file paths.
- `fetch_live_data.py` currently generates demo data when API creds are missing — don't confuse this with real API integration. Check `source` field in responses.
- The `schedule` library in `hourly_refresh.py` is single-threaded — a 5-minute timeout wrapper (`ThreadPoolExecutor` + `FETCH_TIMEOUT_SECONDS`) is in place. Do not remove it.
- **Never return `str(e)` in JSON responses** — this was a recurring bug (found twice in `dashboard_backend.py`, marked "PATCHED" but wasn't). Always grep for `str(e)` in `jsonify()` calls before committing.

### SQLite
- SQLite has no concurrent-write support. Running gunicorn workers + hourly-refresh timer simultaneously can cause `database is locked` errors under load. Consider enabling WAL mode (`PRAGMA journal_mode=WAL`) if this occurs.
- Append-only model: the `INSERT OR REPLACE` pattern in `insert_incident()` replaces the full row on ID collision — entity children are re-inserted without cleaning up old ones first (potential duplicates in `entities` table).
- The SQLite DB path is **relative** (`soc_dashboard.db`). If systemd `WorkingDirectory` is wrong, a new empty DB gets created in a random location. Always verify `WorkingDirectory=/opt/soc-dashboard` in service units.

### Microsoft Graph / Entra ID
- The OAuth2 token URL uses `TENANT_ID` which must be a GUID, not a domain name.
- `SecurityEvents.Read.All` is an **application** permission — it requires admin consent.
- `SecurityIncident.Read.All` is needed for Graph Security incidents API.
- `ThreatIntelligence.Read.All` requires a Defender TI license in the tenant.
- Token responses include `expires_in` (seconds) but no caching is implemented — every page load re-authenticates.
- **User auth uses authorization code flow** (`/common` authority, multi-tenant). The `@require_login` decorator redirects browsers to `/login` and returns 401 for API calls.
- **Admin check uses app roles** — the role name is configurable via `ADMIN_ROLE_NAME` (default `Admin`). Roles must be defined in the Entra app registration manifest.
- **Redirect URI** must be registered in Entra: `https://<domain>/auth/callback`. Missing this causes AADSTS50011 errors.
- **Flask-Session** uses filesystem storage (`flask_sessions/` dir) — must be writable by the service user.

### Config Manager
- `config_manager.py` auto-generates a Fernet key at `CONFIG_KEY_PATH` if missing. **Do not delete `config.key`** — encrypted DB values become unreadable.
- Config priority: DB (encrypted) → environment variable → default/None.
- The `CONFIGURABLE_KEYS` list gates which keys can be set via the settings API. Add new keys there when extending.
- `SECRET_KEYS` frozenset determines which values get Fernet encryption in the DB.

### Frontend
- `soc-dashboard-live.html` loads Chart.js from CDN (`cdn.jsdelivr.net`) — if the CDN is blocked or down (e.g., DMZ network-restricted LXC), charts won't render. Bundle Chart.js locally as fallback.
- CSP headers are set via Flask `@app.after_request` — if adding new external resources, update the CSP policy in `dashboard_backend.py`.

### Deployment / LXC
- **TWO SEPARATE DASHBOARD INSTANCES exist — deploy to the correct one:**
  - `sec.<YOUR_DOMAIN>` → **<PROD_IP>** — production `src/` package app (`src.app:app`), Jinja templates, path `/opt/dashboard/`
  - `report.<YOUR_DOMAIN>` → **<LXC_IP>** (CT 204) — original single-page app (`dashboard_backend:app`), path `/opt/soc-dashboard/`
  - The two codebases are **structurally different** — files from this workspace (`dashboard_backend.py`, `soc-dashboard-live.html`, `auth.py`, `fetch_live_data.py`) belong on **<LXC_IP> (`/opt/soc-dashboard/`)**, NOT on <PROD_IP>.
  - **Always verify the target LXC IP and path before SCP.** Deploying workspace files to the wrong server won't break it (gunicorn loads `src.app:app` on `.50`), but leaves stray files that cause confusion.
- **Proxy protocol required**: CT 204 (<LXC_IP>) nginx expects a PROXY protocol preamble from upstream. Direct connections (bypassing the proxy at <PROXY_IP>) cause `ERR_CONNECTION_RESET`.
- **DNS must point to proxy**: Pi-hole DNS for `report.<YOUR_DOMAIN>` must resolve to `<PROXY_IP>` (www-proxy), **NOT** `<LXC_IP>` (the LXC directly).
- **gunicorn required for production**: Flask's dev server is single-threaded and not suitable for production. Always use gunicorn via `dashboard.service`.
- **`.env` file permissions**: Must be `chmod 600` and owned by the `socdash` service user. `deploy_lxc.sh` sets this, but manual edits can reset permissions.
- **certbot ACME challenge**: Needs HTTP :80 traffic for `report.<YOUR_DOMAIN>` forwarded from the proxy to CT 204. Without this, certificate renewal fails silently.
- No rate limiting on API endpoints.
- No authentication on the dashboard itself — anyone who can reach the proxy can see all data. Access is controlled by network segmentation (DMZ) only.

## Code Conventions

- Python 3.10+ assumed
- Use `python-dotenv` for all config — never import from `config.py`
- Type hints in function signatures (see `database.py` patterns)
- Print statements with emoji prefixes for log readability (e.g., `✅`, `❌`, `⚠️`)
- SQLite parameterised queries: always `?` placeholders with tuple params

## File Roles

| File | Role | Modify When |
|------|------|-------------|
| `dashboard_backend.py` | API server + auth routes + security headers | Adding endpoints, changing response format, updating CSP |
| `database.py` | DB schema + queries | Adding tables, changing schema, new query patterns |
| `fetch_live_data.py` | All external API calls (Graph, Sentinel, TI) | Adding new data sources, fixing API integration |
| `auth.py` | Entra ID login flow + decorators | Changing auth logic, adding scopes, modifying session data |
| `config_manager.py` | Encrypted config CRUD (DB→env fallback) | Adding new configurable keys, changing encryption |
| `append_data.py` | Incremental DB loader | Changing refresh logic |
| `hourly_refresh.py` | Scheduler with configurable interval | Changing refresh interval, timeout settings |
| `soc-dashboard-live.html` | Frontend SPA (auth-gated + settings overlay) | UI changes, new charts/widgets |
| `setup.html` | First-run setup wizard (auto-shown when creds missing) | Changing setup fields, adding validation |
| `scripts/deploy_lxc.sh` | LXC deployment automation | Changing server setup, packages, paths |
| `scripts/setup_systemd.sh` | systemd service/timer setup | Changing gunicorn workers, service config |
| `scripts/nginx_site.conf` | nginx reverse proxy template | TLS config, proxy settings, caching rules |
| `scripts/pre_commit_check.py` | Pre-commit security scanner | Adding new scan patterns |

## Documentation to Update

When making changes, update these docs:
- `docs/ARCHITECTURE.md` — if adding components, APIs, or changing data flow
- `docs/INVENTORY.md` — if adding or removing files
- `docs/SECURITY_FIXES.md` — if finding or fixing vulnerabilities
- `README.md` — if changing setup steps or features
