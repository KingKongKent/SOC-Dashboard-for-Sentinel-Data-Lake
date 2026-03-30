# Security Fixes Tracker

Discovered vulnerabilities, patches applied, and status.

> Last updated: 2025-07-21

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
