# Security Fixes Tracker

Discovered vulnerabilities, patches applied, and status.

> Last updated: 2026-04-20

## Summary

| # | Severity | File | Issue | Status |
|---|----------|------|-------|--------|
| 1 | **HIGH** | dashboard_backend.py | Flask `debug=True` in production — exposes Werkzeug debugger (RCE) | **PATCHED** |
| 2 | **MEDIUM** | dashboard_backend.py | `host='0.0.0.0'` binds to all interfaces — unintended network exposure | **PATCHED** |
| 3 | **MEDIUM** | dashboard_backend.py | `CORS(app)` with no origin restriction — allows any origin | **PATCHED** |
| 4 | **LOW** | database.py | `f" LIMIT {limit}"` — format-string SQL (limit is int-typed but not parameterised) | **PATCHED** |
| 5 | **LOW** | dashboard_backend.py | `str(e)` returned in JSON error responses — may leak internal paths/stack | **PATCHED** |
| 6 | **INFO** | SECURITY.md | Default GitHub template with fake version numbers — not project-specific | **PATCHED** |
| 7 | **MEDIUM** | dashboard_backend.py | No security headers (CSP, X-Frame-Options) — vulnerable to XSS/clickjacking | **PATCHED** |
| 8 | **LOW** | hourly_refresh.py | No fetch timeout — hanging API call blocks scheduler indefinitely | **PATCHED** |
| 9 | **HIGH** | dashboard_backend.py | No authentication — anyone on the network can access all SOC data | **PATCHED** |
| 10 | **MEDIUM** | fetch_live_data.py | Credentials stored in plaintext .env only — no encrypted storage option | **PATCHED** |
| 11 | **MEDIUM** | fetch_live_data.py | `Mail.Send` as application permission — tenant-wide send-as-any-user | **PATCHED** |
| 12 | **LOW** | dashboard_backend.py | Graph comment exceeds 1000-char limit — silent 400 rejection | **PATCHED** |
| 13 | **INFO** | dashboard_backend.py | Flask logger not wired to gunicorn — app.logger output silently lost | **PATCHED** |
| 14 | **LOW** | dashboard_backend.py | Settings ALLOWED set missing new config keys — silent data loss on save | **PATCHED** |
| 15 | **MEDIUM** | dashboard_backend.py | Synchronous `/api/refresh` blocks gunicorn worker for ~8 min — causes 502 timeout | **PATCHED** |
| 16 | **LOW** | database.py | Workspace seeded with `.env.example` placeholder (`your-workspace-id`) | **PATCHED** |
| 17 | **LOW** | soc-dashboard-live.html | MDTI section visible by default before feature flags load | **PATCHED** |
| 18 | **LOW** | soc-dashboard-live.html | DEMO badge shown on empty DB (0 incidents → source `none`) | **PATCHED** |

---

## Detail

### 1. Flask debug=True (HIGH)

**Risk:** Werkzeug interactive debugger allows arbitrary Python execution from the browser.  
**Fix:** Read `FLASK_DEBUG` from env, default `False`. Debug mode only when explicitly set.

```python
# Before
app.run(host='0.0.0.0', port=5000, debug=True)

# After
app.run(
    host=os.getenv('FLASK_HOST', '127.0.0.1'),
    port=int(os.getenv('FLASK_PORT', '5000')),
    debug=os.getenv('FLASK_DEBUG', '0') == '1'
)
```

### 2. Bind to 0.0.0.0 (MEDIUM)

**Risk:** Exposes the dashboard on all network interfaces. Anyone on the network can access it.  
**Fix:** Default to `127.0.0.1` (localhost only). Override via `FLASK_HOST` env var when needed.

### 3. CORS wildcard (MEDIUM)

**Risk:** Any website can make cross-origin requests to the API, including reading response data.  
**Fix:** Restrict CORS to localhost origins by default. Add `CORS_ORIGINS` env var for customisation.

```python
# Before
CORS(app)

# After
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000')
CORS(app, origins=cors_origins.split(','))
```

### 4. SQL LIMIT via f-string (LOW)

**Risk:** Although `limit` is typed as `Optional[int]`, using f-string formatting bypasses SQLite's parameter binding. If the call site ever passes unsanitised input, this becomes injectable.  
**Fix:** Use parameterised query for LIMIT.

```python
# Before
query += f" LIMIT {limit}"

# After
query += " LIMIT ?"
params.append(limit)
```

### 5. Error message leaking (LOW)

**Risk:** `str(e)` in API responses can expose file paths, database paths, or stack details.  
**Found in:** `/api/database-stats` (line 200) and JSON decode handler (line 179).  
**Note:** Was originally marked PATCHED but `str(e)` was still present in two locations.  
**Fix:** Return generic error messages to clients; log the real error server-side only.

```python
# Before (line 200)
return jsonify({'error': str(e)}), 500

# After
print(f"❌ Database stats error: {e}")
return jsonify({'error': 'Failed to retrieve database statistics'}), 500
```

### 6. SECURITY.md placeholder (INFO)

**Risk:** Misleading version table from GitHub template.  
**Fix:** Replaced with project-specific security policy.

### 11. Mail.Send over-permission (MEDIUM)

**Risk:** `Mail.Send` was configured as an **application** permission (client_credentials flow). This
granted the app the ability to call `POST /users/{any-oid}/sendMail` for any user in the tenant —
far broader than needed for escalation notifications.  
**Fix:**
- Removed application-level `Mail.Send` permission.
- Added `Mail.Send` as a **delegated** permission, consented at user login.
- `graph_send_mail()` now accepts a delegated token and calls `POST /me/sendMail` — can only send
  as the currently logged-in user.
- MSAL token cache is persisted in the Flask session so `acquire_token_silent()` can retrieve the
  user's delegated access token when the escalation email fires.
- If the delegated token is unavailable, the escalation still succeeds (severity bump + tag +
  comment + DB update); only the email is skipped with a warning log.

### 7. Missing security headers (MEDIUM)

**Risk:** No `Content-Security-Policy`, `X-Frame-Options`, or `X-Content-Type-Options` headers.
The SPA is vulnerable to XSS via injected scripts and clickjacking via iframe embedding.  
**Fix:** Added `@app.after_request` handler in `dashboard_backend.py` setting:
- `Content-Security-Policy` — restricts script/style sources to `'self'` + `cdn.jsdelivr.net`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 8. Scheduler fetch timeout (LOW)

**Risk:** `hourly_refresh.py` uses the single-threaded `schedule` library. If an API call
in `fetch_and_append_new_data()` hangs indefinitely, the scheduler blocks and all
subsequent refresh cycles are missed.  
**Fix:** Wrap the fetch call in `concurrent.futures.ThreadPoolExecutor` with a 5-minute
(`FETCH_TIMEOUT_SECONDS = 300`) timeout. On timeout, the cycle is logged and skipped.

### 9. No dashboard authentication (HIGH)

**Risk:** The dashboard had no authentication — anyone who could reach the proxy could view
all SOC incident data, secure scores, and threat intel.  
**Fix:** Added Entra ID OAuth2 authorization code flow via MSAL (`auth.py`). All routes now
require login (`@require_login`). Admin-only routes use `@require_admin` based on Entra app roles.
Sessions stored server-side via Flask-Session (filesystem) with 8-hour lifetime and SameSite=Lax.

### 10. Credentials stored in plaintext only (MEDIUM)

**Risk:** All API credentials (CLIENT_SECRET, VIRUSTOTAL_API_KEY, etc.) existed only in the
`.env` file with no encryption. If the file was read by an attacker, all secrets were exposed.  
**Fix:** Added `config_manager.py` with Fernet (AES-128-CBC) encryption. Secrets stored in the
SQLite `config` table are encrypted at rest using an auto-generated key at `CONFIG_KEY_PATH`.
The `.env` file remains as a fallback for bootstrap credentials.

### 12. Graph comment exceeds 1000-char limit (LOW)

**Risk:** The Graph Security API enforces a 1000-character maximum per incident comment.
AI Analysis and Security Copilot enrichment summaries exceeded this limit (up to ~1700 chars),
causing a `400 Bad Request` error. The comment was silently not posted; no error was visible
because Flask's logger was not wired to gunicorn (see #13).
**Fix:**
- `graph_post_comment()` in `fetch_live_data.py` now auto-truncates to `[:1000]` as a safety net.
- AI Analysis comment: analysis truncated to 960 chars, final `[:1000]` applied.
- Copilot Enrichment comment: summary truncated to 700 chars, actions to 80 chars each × 5 max,
  final `[:1000]` applied.

### 13. Flask logger not wired to gunicorn (INFO)

**Risk:** `app.logger.info()` and `app.logger.warning()` calls produced no output in gunicorn's
error log. This made debugging production issues impossible — errors from comment posting,
enrichment, and authentication were invisible even with `--capture-output` on gunicorn.
**Fix:** Added at startup in `dashboard_backend.py`:
```python
_gunicorn_logger = logging.getLogger('gunicorn.error')
if _gunicorn_logger.handlers:
    app.logger.handlers = _gunicorn_logger.handlers
    app.logger.setLevel(_gunicorn_logger.level)
```
All `app.logger` output now appears in `/var/log/soc-dashboard/error.log`.

### 14. Settings ALLOWED set missing new config keys (LOW)

**Risk:** The `ALLOWED` set in the `/api/settings` PUT endpoint gates which config keys can be
saved. When Security Copilot feature toggles were added (`SECURITY_COPILOT_ENABLED`,
`COPILOT_AUTO_ENRICH_ENABLED`, `COPILOT_AUTO_ENRICH_MAX_PER_CYCLE`, `COPILOT_WEBHOOK_SECRET`),
they were not added to the `ALLOWED` set. Settings saves silently dropped these keys — the admin
UI showed the toggles as enabled, but after page refresh they reverted to disabled because the
values were never persisted.
**Fix:** Added all four Copilot keys to the `ALLOWED` set. This is a recurring pattern —
**always update `ALLOWED` when adding new settings keys**.

### 15. Synchronous refresh blocks gunicorn worker (MEDIUM)

**Risk:** `POST /api/refresh` ran `fetch_and_append_new_data()` synchronously inside a gunicorn
worker. The fetch cycle takes ~8 minutes (50 individual `/security/incidents/{id}/alerts` Graph API
calls). This blocked the worker, causing 502 gateway timeouts for all other clients sharing that
worker, and `systemctl restart dashboard` killed the fetch mid-run (daemon thread).
**Fix:**
- `/api/refresh` now starts a background `threading.Thread(daemon=True)` and returns immediately
  with status `started`.
- New `/api/refresh/status` endpoint returns `{status: 'idle'|'running'|'completed'|'error',
  started_at, last_completed, last_error}` for polling.
- Frontend polls `/api/refresh/status` every 5 seconds during refresh and shows animated
  progress messages.
- Added a threading lock to prevent concurrent refresh runs.

### 16. Workspace seeded with placeholder values (LOW)

**Risk:** `database.py` seeded the `workspaces` table from config during `init_db()`. If
`SENTINEL_WORKSPACE_ID` was still the `.env.example` placeholder (`your-workspace-id`), it got
inserted as a real workspace row. This caused spurious errors when KQL queries ran against a
non-existent workspace.
**Fix:** Added guard in `init_db()` to skip workspace seeding if the value matches common
placeholder patterns (`your-`, empty string, `None`).

### 17. MDTI section visible before feature flags load (LOW)

**Risk:** The `<div id="mdtiSection">` was rendered visible in the initial HTML. For the brief
window between page load and `/api/features` response, MDTI data (if cached from a previous
session) could be visible to users without MDTI enabled. Minor info leak of threat intel article
titles.
**Fix:** Added `style="display:none"` to the `<div id="mdtiSection">` element so it starts
hidden and is only shown when `/api/features` confirms `mdti_enabled: true`.

### 18. DEMO badge on empty database (LOW)

**Risk:** The DEMO badge logic checked `source === 'demo'` but when the database was empty (0
incidents after a fresh deploy), the response had no `source` field, which was coerced to `none` —
not matching `demo`, but the fallback condition still triggered the badge. Confusing for users who
had configured real credentials but hadn't fetched data yet.
**Fix:** Updated DEMO badge condition to only show when `source` is explicitly `'demo'`, not when
data is simply absent.
