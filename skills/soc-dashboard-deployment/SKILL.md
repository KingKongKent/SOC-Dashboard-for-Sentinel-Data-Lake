---
name: soc-dashboard-deployment
description: >
  Domain knowledge for deploying the SOC Dashboard to an Ubuntu 24.04 LXC
  behind an nginx/SNI proxy with TLS, systemd services, and Pi-hole DNS.
  USE FOR: deploy dashboard, set up LXC, configure nginx, systemd service,
  TLS certificate, Pi-hole DNS, proxy_protocol, gunicorn config, production setup.
  DO NOT USE FOR: general Azure, Sentinel queries, or frontend development.
---

# SOC Dashboard — Deployment Skill

## Target Environment

| Detail | Value |
|--------|-------|
| **LXC** | CT 204 `report-dashboard` |
| **Node** | pve2 |
| **OS** | Ubuntu 24.04 |
| **IP** | <LXC_IP> (DMZ, vmbr1) |
| **Domain** | report.<YOUR_DOMAIN> |
| **SSH** | Key-based (no password) |

## Architecture

```
Browser
  → Pi-hole DNS (report.<YOUR_DOMAIN> → <PROXY_IP>)
    → www-proxy (<PROXY_IP>) nginx stream SNI router :443
      → proxy_protocol ON → CT 204 (<LXC_IP>:443)
        → nginx (TLS termination + proxy_protocol)
          → gunicorn (127.0.0.1:5000, 2 workers)
            → Flask (dashboard_backend.py)
              → SQLite (/var/lib/soc-dashboard/soc_dashboard.db)
```

## Deployment Steps

### 1. Copy files to LXC
```powershell
# From Windows workspace
$files = "*.py", "requirements.txt", ".env.example", "soc-dashboard-live.html"
scp $files root@<LXC_IP>:/opt/soc-dashboard/
scp -r scripts root@<LXC_IP>:/opt/soc-dashboard/
```

### 2. Run deployment script
```bash
ssh root@<LXC_IP> 'bash /opt/soc-dashboard/scripts/deploy_lxc.sh'
```

### 3. Configure credentials
```bash
ssh root@<LXC_IP>
nano /opt/soc-dashboard/.env
# Fill: CLIENT_ID, CLIENT_SECRET, TENANT_ID, SENTINEL_WORKSPACE_ID, etc.
# Add: FLASK_HOST=127.0.0.1
# Add: CORS_ORIGINS=https://report.<YOUR_DOMAIN>
systemctl restart dashboard
```

### 4. Initial data fetch
```bash
sudo -u socdash /opt/soc-dashboard/venv/bin/python /opt/soc-dashboard/fetch_live_data.py
```

### 5. DNS (Pi-hole)
Add local DNS override on Pi-hole:
```
report.<YOUR_DOMAIN> → <PROXY_IP>   # Points to PROXY, not LXC!
```

### 6. SNI route on www-proxy (<PROXY_IP>)
Add to `nginx.conf` stream map:
```nginx
# In the stream { map $ssl_preread_server_name $backend { ... } } block:
report.<YOUR_DOMAIN>    <LXC_IP>:443;
```
Then: `nginx -t && systemctl reload nginx`

### 7. TLS certificate
On CT 204:
```bash
certbot --nginx -d report.<YOUR_DOMAIN>
```
**Note:** ACME challenge goes through the proxy — the proxy must forward `:80` for
`report.<YOUR_DOMAIN>` to `<LXC_IP>:80`. Add an HTTP server block on the proxy
or a stream map for port 80.

## Systemd Services

| Unit | Type | Purpose |
|------|------|---------|
| `dashboard.service` | notify (gunicorn) | Flask API + HTML serving |
| `hourly-refresh.service` | oneshot | Single data fetch run |
| `hourly-refresh.timer` | timer | Triggers refresh every hour |

### Useful commands
```bash
systemctl status dashboard
systemctl restart dashboard
journalctl -u dashboard -f           # Live logs
systemctl list-timers                 # Check timer schedule
journalctl -u hourly-refresh -n 50   # Last refresh log
```

## Known Pitfalls

### Proxy Protocol
- Direct connections to `<LXC_IP>:443` (bypassing proxy) cause `ERR_CONNECTION_RESET`
  because nginx expects a PROXY protocol preamble as the first bytes.
- **Always access via the proxy** (<PROXY_IP>) or through DNS.
- To test directly: `curl` from <PROXY_IP> using `--resolve report.<YOUR_DOMAIN>:443:127.0.0.1`

### DNS Must Point to Proxy
- Pi-hole DNS for `report.<YOUR_DOMAIN>` MUST resolve to `<PROXY_IP>` (the proxy),
  **NOT** `<LXC_IP>` (the LXC directly).
- If DNS points directly to the LXC, TLS handshake fails (no proxy_protocol preamble).

### SQLite Locking
- gunicorn workers + hourly-refresh can collide on writes.
- The systemd oneshot service runs `append_data.py` directly (not `hourly_refresh.py`),
  so the timeout wrapper isn't in play — rely on `TimeoutStartSec=600` in the unit.
- If `database is locked` errors appear under load, consider enabling WAL mode:
  ```python
  conn.execute("PRAGMA journal_mode=WAL")
  ```

### .env File Permissions
- Must be `chmod 600` and owned by the `socdash` user.
- `deploy_lxc.sh` sets this automatically, but verify after manual edits.

### WorkingDirectory
- Both systemd units set `WorkingDirectory=/opt/soc-dashboard`.
- The SQLite DB path in `database.py` is relative (`soc_dashboard.db`) — if WorkingDirectory
  is wrong, a new empty DB gets created in a random location.
- For production, consider the `DB_DIR` approach: store DB in `/var/lib/soc-dashboard/`.

### Chart.js CDN
- The frontend loads Chart.js from `cdn.jsdelivr.net`. If the LXC is in a network-restricted
  DMZ segment, charts won't render.
- Fallback: download Chart.js locally and update the `<script src>` in the HTML.

### No Dashboard Authentication
- The Flask app has no login/auth layer. Anyone who can reach port 5000 (or the nginx
  proxy) can see all security data.
- Access is currently controlled by network segmentation (DMZ) and DNS-based routing only.
- For authenticated access, add Flask-Login or a reverse proxy auth layer (e.g., Authelia).
