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
| **IP** | 192.168.7.20 (DMZ, vmbr1) |
| **Domain** | report.kents-events.com |
| **SSH** | Key-based (no password) |

## Architecture

```
Browser
  → Pi-hole DNS (report.kents-events.com → 192.168.7.10)
    → www-proxy (192.168.7.10) nginx stream SNI router :443
      → proxy_protocol ON → CT 204 (192.168.7.20:443)
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
scp $files root@192.168.7.20:/opt/soc-dashboard/
scp -r scripts root@192.168.7.20:/opt/soc-dashboard/
```

### 2. Run deployment script
```bash
ssh root@192.168.7.20 'bash /opt/soc-dashboard/scripts/deploy_lxc.sh'
```

### 3. Configure credentials
```bash
ssh root@192.168.7.20
nano /opt/soc-dashboard/.env
# Fill: CLIENT_ID, CLIENT_SECRET, TENANT_ID, SENTINEL_WORKSPACE_ID, etc.
# Add: FLASK_HOST=127.0.0.1
# Add: CORS_ORIGINS=https://report.kents-events.com
systemctl restart dashboard
```

### 4. Initial data fetch
```bash
sudo -u socdash /opt/soc-dashboard/venv/bin/python /opt/soc-dashboard/fetch_live_data.py
```

### 5. DNS (Pi-hole)
Add local DNS override on Pi-hole:
```
report.kents-events.com → 192.168.7.10   # Points to PROXY, not LXC!
```

### 6. SNI route on www-proxy (192.168.7.10)
Add to `nginx.conf` stream map:
```nginx
# In the stream { map $ssl_preread_server_name $backend { ... } } block:
report.kents-events.com    192.168.7.20:443;
```
Then: `nginx -t && systemctl reload nginx`

### 7. TLS certificate
On CT 204:
```bash
certbot --nginx -d report.kents-events.com
```
**Note:** ACME challenge goes through the proxy — the proxy must forward `:80` for
`report.kents-events.com` to `192.168.7.20:80`. Add an HTTP server block on the proxy
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
- Direct connections to `192.168.7.20:443` (bypassing proxy) cause `ERR_CONNECTION_RESET`
  because nginx expects a PROXY protocol preamble as the first bytes.
- **Always access via the proxy** (192.168.7.10) or through DNS.
- To test directly: `curl` from 192.168.7.10 using `--resolve report.kents-events.com:443:127.0.0.1`

### DNS Must Point to Proxy
- Pi-hole DNS for `report.kents-events.com` MUST resolve to `192.168.7.10` (the proxy),
  **NOT** `192.168.7.20` (the LXC directly).
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
