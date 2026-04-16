<#
.SYNOPSIS
    Collect debug logs and status from remote SOC Dashboard installations.

.DESCRIPTION
    SSHs into one or more remote hosts running the SOC Dashboard and
    collects service status, error logs, resource usage, DB health,
    certificate info, nginx/proxy diagnostics, and connectivity checks.
    Output is saved to a timestamped file under .\debug-logs\.

    Works with any installation — auto-discovers paths (FHS layout,
    single-dir layout, or custom paths). Includes specific diagnostics
    for the common "Error handling request (no URI read)" gunicorn error
    caused by proxy_protocol misconfiguration.

.PARAMETER Hosts
    One or more SSH targets (user@host). No default — you must specify.

.PARAMETER SshPort
    SSH port to use. Default: 22.

.PARAMETER Lines
    Number of recent log lines to collect. Default: 200.

.PARAMETER All
    Include access logs in addition to error logs.

.PARAMETER GenerateBash
    Instead of SSHing, output the collection script to stdout / file so
    the remote user can run it themselves (no SSH access needed).

.EXAMPLE
    .\scripts\collect_remote_logs.ps1 -Hosts "root@10.0.0.5"
    .\scripts\collect_remote_logs.ps1 -Hosts "user@server1","user@server2" -SshPort 2222
    .\scripts\collect_remote_logs.ps1 -Lines 500 -All -Hosts "root@10.0.0.5"
    .\scripts\collect_remote_logs.ps1 -GenerateBash | Set-Content -Path collect.sh
#>

param(
    [string[]]$Hosts,
    [int]$SshPort = 22,
    [int]$Lines = 200,
    [switch]$All,
    [switch]$GenerateBash
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outDir = Join-Path $PSScriptRoot "..\debug-logs"

# ── Remote collection script (bash) ──────────────────────────
# Sent via SSH stdin — no SCP needed. Also usable standalone.
$remoteScript = @"
#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — Remote Debug Collector
# =============================================================
# Auto-discovers installation paths. Run as root or with sudo.
# Usage (standalone): bash collect_debug.sh [LINES] [COLLECT_ACCESS]
# =============================================================
set -uo pipefail

LINES=\${1:-__LINES__}
COLLECT_ACCESS=\${2:-__ACCESS__}

# ── Auto-discover installation paths ─────────────────────────
APP_DIR=""
for candidate in /opt/soc-dashboard /opt/dashboard /srv/soc-dashboard; do
    if [ -d "\$candidate" ] && [ -f "\$candidate/dashboard_backend.py" ]; then
        APP_DIR="\$candidate"
        break
    fi
done
if [ -z "\$APP_DIR" ]; then
    # Last resort: find it
    APP_DIR=\$(find / -maxdepth 3 -name "dashboard_backend.py" -type f -printf '%h\n' 2>/dev/null | head -1)
fi

VENV_DIR=""
for candidate in /usr/local/soc-venv "\${APP_DIR}/venv" "\${APP_DIR}/.venv" /opt/venv; do
    if [ -f "\${candidate}/bin/python" ] 2>/dev/null; then
        VENV_DIR="\$candidate"
        break
    fi
done

DB_DIR=""
DB_FILE=""
for candidate in /var/lib/soc-dashboard "\$APP_DIR"; do
    if [ -f "\${candidate}/soc_dashboard.db" ] 2>/dev/null; then
        DB_DIR="\$candidate"
        DB_FILE="\${candidate}/soc_dashboard.db"
        break
    fi
done
if [ -z "\$DB_FILE" ]; then
    DB_FILE=\$(find / -maxdepth 4 -name "soc_dashboard.db" -type f 2>/dev/null | head -1)
    [ -n "\$DB_FILE" ] && DB_DIR=\$(dirname "\$DB_FILE")
fi

CONF_DIR=""
ENV_FILE=""
for candidate in /etc/soc-dashboard "\$APP_DIR"; do
    if [ -f "\${candidate}/.env" ] 2>/dev/null; then
        CONF_DIR="\$candidate"
        ENV_FILE="\${candidate}/.env"
        break
    fi
done

LOG_DIR=""
for candidate in /var/log/soc-dashboard "\$APP_DIR"; do
    if [ -f "\${candidate}/error.log" ] 2>/dev/null; then
        LOG_DIR="\$candidate"
        break
    fi
done

sep() { echo ""; echo "========== \$1 =========="; }

# ──────────────────────────────────────────────────────────────
sep "HOSTNAME & DATE"
hostname -f 2>/dev/null || hostname
date -Iseconds
uptime

sep "DISCOVERED PATHS"
echo "  APP_DIR:  \${APP_DIR:-NOT FOUND}"
echo "  VENV_DIR: \${VENV_DIR:-NOT FOUND}"
echo "  DB_FILE:  \${DB_FILE:-NOT FOUND}"
echo "  ENV_FILE: \${ENV_FILE:-NOT FOUND}"
echo "  LOG_DIR:  \${LOG_DIR:-NOT FOUND}"

sep "OS RELEASE"
cat /etc/os-release 2>/dev/null | head -5

sep "RESOURCE USAGE"
echo "--- Memory ---"
free -h 2>/dev/null || cat /proc/meminfo 2>/dev/null | head -3
echo ""
echo "--- Disk ---"
df -h / /var /opt 2>/dev/null | sort -u
echo ""
echo "--- Top 5 CPU ---"
ps aux --sort=-%cpu 2>/dev/null | head -6

# ──────────────────────────────────────────────────────────────
sep "SERVICE STATUS"
for svc in dashboard.service hourly-refresh.timer hourly-refresh.service nginx; do
    echo "--- \$svc ---"
    systemctl is-active "\$svc" 2>/dev/null || echo "not found"
    systemctl is-enabled "\$svc" 2>/dev/null || true
    echo ""
done

sep "DASHBOARD SERVICE DETAILS"
systemctl status dashboard.service --no-pager -l 2>/dev/null || echo "Service not found"

sep "HOURLY REFRESH TIMER"
systemctl list-timers hourly-refresh.timer --no-pager 2>/dev/null || echo "Timer not found"

# ──────────────────────────────────────────────────────────────
sep "GUNICORN PROCESS CHECK"
ps aux | grep -E '[g]unicorn|[d]ashboard_backend' || echo "No gunicorn processes found"

sep "LISTENING PORTS"
ss -tlnp 2>/dev/null | grep -E ':5000|:443|:80|gunicorn' || echo "No relevant listeners"

# ──────────────────────────────────────────────────────────────
sep "NGINX STATUS & CONFIG DIAGNOSTICS"
if command -v nginx &>/dev/null; then
    systemctl status nginx --no-pager -l 2>/dev/null | head -20
    echo ""
    echo "--- nginx -t ---"
    nginx -t 2>&1 || true
    echo ""

    echo "--- proxy_protocol detection ---"
    PP_FOUND=false
    for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/nginx.conf; do
        if [ -f "\$conf" ] && grep -q "proxy_protocol" "\$conf" 2>/dev/null; then
            PP_FOUND=true
            echo "  proxy_protocol ENABLED in: \$conf"
            grep -n "proxy_protocol\|listen.*443\|set_real_ip_from\|real_ip_header" "\$conf" 2>/dev/null | sed 's/^/    /'
            echo ""
        fi
    done
    if [ "\$PP_FOUND" = false ]; then
        echo "  proxy_protocol: NOT configured in any nginx config"
    fi

    echo ""
    echo "--- upstream proxy_pass targets ---"
    grep -rn "proxy_pass" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | sed 's/^/  /' || echo "  No proxy_pass directives"
else
    echo "nginx not installed"
fi

# ──────────────────────────────────────────────────────────────
sep "PROXY PROTOCOL DIAGNOSIS"
echo "Checking for 'no URI read' errors (proxy_protocol mismatch)..."
URI_ERRORS=0
if [ -n "\$LOG_DIR" ] && [ -f "\$LOG_DIR/error.log" ]; then
    URI_ERRORS=\$(grep -c "no URI read\|Invalid HTTP_HOST\|PROXY.*Invalid" "\$LOG_DIR/error.log" 2>/dev/null || echo 0)
fi
JOURNAL_URI=\$(journalctl -u dashboard.service --no-pager -q 2>/dev/null | grep -c "no URI read" || echo 0)
echo "  'no URI read' in error.log:  \$URI_ERRORS occurrences"
echo "  'no URI read' in journal:    \$JOURNAL_URI occurrences"

if [ "\$URI_ERRORS" -gt 0 ] || [ "\$JOURNAL_URI" -gt 0 ]; then
    echo ""
    echo "  ⚠️  LIKELY CAUSE: proxy_protocol mismatch between nginx and gunicorn."
    echo "  Common scenarios:"
    echo "    1. nginx has 'listen 443 ssl proxy_protocol' but nothing sends proxy_protocol to it"
    echo "       → Fix: remove 'proxy_protocol' from nginx listen directives"
    echo "    2. An upstream proxy sends proxy_protocol to nginx, but nginx forwards to"
    echo "       gunicorn with the proxy_protocol preamble still attached"
    echo "       → Fix: nginx should strip it (normal proxy_pass does this automatically)"
    echo "    3. Health-check probes or scanners connect to port 443 without TLS/HTTP"
    echo "       → Usually harmless; filter from monitoring"
    echo ""
    echo "  Last 5 'no URI read' entries from error.log:"
    grep "no URI read" "\$LOG_DIR/error.log" 2>/dev/null | tail -5 | sed 's/^/    /'
fi

# ──────────────────────────────────────────────────────────────
sep "PYTHON / VENV"
if [ -n "\$VENV_DIR" ] && [ -f "\$VENV_DIR/bin/python" ]; then
    echo "Venv: \$VENV_DIR"
    "\$VENV_DIR/bin/python" --version 2>&1
    echo ""
    echo "--- Key packages ---"
    "\$VENV_DIR/bin/pip" list 2>/dev/null | grep -iE 'flask|gunicorn|msal|azure|openai|requests|cryptography|python-dotenv' || true
else
    echo "No venv found"
    which python3 2>/dev/null && python3 --version 2>&1
fi

# ──────────────────────────────────────────────────────────────
sep "DATABASE HEALTH"
if [ -n "\$DB_FILE" ] && [ -f "\$DB_FILE" ]; then
    echo "Database: \$DB_FILE"
    ls -lh "\$DB_FILE"
    echo ""

    if command -v sqlite3 &>/dev/null; then
        echo "--- Integrity check ---"
        sqlite3 "\$DB_FILE" "PRAGMA integrity_check;" 2>&1 || echo "DB locked or corrupt"
        echo ""
        echo "--- Journal mode ---"
        sqlite3 "\$DB_FILE" "PRAGMA journal_mode;" 2>&1
        echo ""
        echo "--- Table row counts ---"
        for tbl in incidents alerts entities threat_intel_snapshots metrics_snapshots config cases attack_stories; do
            count=\$(sqlite3 "\$DB_FILE" "SELECT count(*) FROM \$tbl;" 2>/dev/null || echo "N/A")
            printf "  %-30s %s\n" "\$tbl" "\$count"
        done
        echo ""
        echo "--- Latest incident ---"
        sqlite3 "\$DB_FILE" "SELECT id, title, severity, status, created_time FROM incidents ORDER BY created_time DESC LIMIT 3;" 2>/dev/null || echo "No incidents"
        echo ""
        echo "--- Latest metrics snapshot ---"
        sqlite3 "\$DB_FILE" "SELECT timestamp, secure_score, total_incidents FROM metrics_snapshots ORDER BY timestamp DESC LIMIT 1;" 2>/dev/null || echo "No metrics"
        echo ""
        echo "--- Data freshness ---"
        echo "  Newest incident:  \$(sqlite3 "\$DB_FILE" "SELECT max(created_time) FROM incidents;" 2>/dev/null || echo "N/A")"
        echo "  Newest alert:     \$(sqlite3 "\$DB_FILE" "SELECT max(timestamp) FROM alerts;" 2>/dev/null || echo "N/A")"
        echo "  Newest metric:    \$(sqlite3 "\$DB_FILE" "SELECT max(timestamp) FROM metrics_snapshots;" 2>/dev/null || echo "N/A")"
        echo "  Newest TI:        \$(sqlite3 "\$DB_FILE" "SELECT max(timestamp) FROM threat_intel_snapshots;" 2>/dev/null || echo "N/A")"
    else
        echo "sqlite3 not installed — skipping DB queries"
        echo "Install: apt-get install -y sqlite3"
    fi
else
    echo "No database found"
    echo "Searching..."
    find / -maxdepth 4 -name "soc_dashboard.db" -type f 2>/dev/null || echo "  Not found anywhere"
fi

# ──────────────────────────────────────────────────────────────
sep "CONFIG FILE CHECK"
if [ -n "\$ENV_FILE" ] && [ -f "\$ENV_FILE" ]; then
    echo ".env found at: \$ENV_FILE"
    ls -la "\$ENV_FILE"
    echo ""
    echo "--- Configured keys (values redacted) ---"
    grep -v '^\s*#' "\$ENV_FILE" | grep -v '^\s*$' | sed 's/=.*/=****/' | sort
    echo ""
    echo "--- Critical keys check ---"
    for key in CLIENT_ID CLIENT_SECRET TENANT_ID WORKSPACE_ID LOG_ANALYTICS_WORKSPACE_ID SECRET_KEY; do
        if grep -q "^\${key}=" "\$ENV_FILE" 2>/dev/null; then
            val=\$(grep "^\${key}=" "\$ENV_FILE" | head -1 | cut -d= -f2-)
            if [ -z "\$val" ] || [ "\$val" = '""' ] || [ "\$val" = "''" ] || echo "\$val" | grep -qiE 'your[-_]|placeholder|changeme|xxx'; then
                echo "  ⚠️  \$key = EMPTY or PLACEHOLDER"
            else
                echo "  ✅ \$key = configured"
            fi
        else
            echo "  ❌ \$key = MISSING from .env"
        fi
    done
else
    echo "No .env found in standard locations"
fi

sep "ENCRYPTION KEY"
KEY_FILE=""
for candidate in /var/lib/soc-dashboard/config.key "\${APP_DIR}/config.key"; do
    if [ -f "\$candidate" ] 2>/dev/null; then
        KEY_FILE="\$candidate"
        break
    fi
done
if [ -n "\$KEY_FILE" ]; then
    echo "config.key present at \$KEY_FILE"
    ls -la "\$KEY_FILE"
else
    echo "⚠️  No config.key found — encrypted config values will be unreadable"
fi

sep "FLASK SESSIONS"
SESSION_DIR=""
for candidate in /var/lib/soc-dashboard/flask_sessions "\${APP_DIR}/flask_sessions"; do
    if [ -d "\$candidate" ] 2>/dev/null; then
        SESSION_DIR="\$candidate"
        break
    fi
done
if [ -n "\$SESSION_DIR" ]; then
    session_count=\$(find "\$SESSION_DIR" -type f | wc -l)
    echo "Session dir: \$SESSION_DIR"
    echo "Session files: \$session_count"
    if [ "\$session_count" -gt 0 ]; then
        echo "Oldest: \$(find "\$SESSION_DIR" -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -1)"
        echo "Newest: \$(find "\$SESSION_DIR" -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -1)"
    fi
else
    echo "No flask_sessions directory found"
fi

# ──────────────────────────────────────────────────────────────
sep "TLS CERTIFICATE"
found_cert=false
for cert_path in /etc/letsencrypt/live/*/fullchain.pem; do
    if [ -f "\$cert_path" ]; then
        found_cert=true
        echo "--- \$cert_path ---"
        openssl x509 -in "\$cert_path" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || echo "openssl not available"
        echo ""
    fi
done
# Check self-signed certs in common locations
for cert_path in /etc/ssl/certs/soc-dashboard*.pem /etc/nginx/ssl/*.pem; do
    if [ -f "\$cert_path" ] 2>/dev/null; then
        found_cert=true
        echo "--- \$cert_path ---"
        openssl x509 -in "\$cert_path" -noout -subject -issuer -dates 2>/dev/null || true
        echo ""
    fi
done
[ "\$found_cert" = false ] && echo "No TLS certificates found"

# ──────────────────────────────────────────────────────────────
sep "ERROR LOG (last \$LINES lines)"
if [ -n "\$LOG_DIR" ] && [ -f "\$LOG_DIR/error.log" ]; then
    ls -lh "\$LOG_DIR/error.log"
    echo ""
    echo "--- Error summary (top 10 patterns) ---"
    grep -oP '(?<=\] ).*' "\$LOG_DIR/error.log" 2>/dev/null | sort | uniq -c | sort -rn | head -10 || true
    echo ""
    echo "--- Last \$LINES lines ---"
    tail -n "\$LINES" "\$LOG_DIR/error.log"
else
    echo "No error.log found"
    # Try to find it
    found_log=\$(find /var/log -name "error.log" -path "*soc*" -o -name "error.log" -path "*dashboard*" 2>/dev/null | head -1)
    if [ -n "\$found_log" ]; then
        echo "Found log at: \$found_log"
        tail -n "\$LINES" "\$found_log"
    fi
fi

sep "JOURNALCTL — dashboard.service (last \$LINES lines)"
journalctl -u dashboard.service --no-pager -n "\$LINES" 2>/dev/null || echo "No journal entries"

sep "JOURNALCTL — hourly-refresh (last 50 lines)"
journalctl -u hourly-refresh.service --no-pager -n 50 2>/dev/null || echo "No journal entries"

if [ "\$COLLECT_ACCESS" = "1" ]; then
    sep "ACCESS LOG (last \$LINES lines)"
    if [ -n "\$LOG_DIR" ] && [ -f "\$LOG_DIR/access.log" ]; then
        ls -lh "\$LOG_DIR/access.log"
        echo ""
        tail -n "\$LINES" "\$LOG_DIR/access.log"
    else
        echo "No access.log found"
    fi
fi

sep "LOGROTATE"
found_lr=false
for lr in /etc/logrotate.d/soc-dashboard /etc/logrotate.d/dashboard; do
    if [ -f "\$lr" ]; then
        found_lr=true
        echo "--- \$lr ---"
        cat "\$lr"
    fi
done
[ "\$found_lr" = false ] && echo "No logrotate config for soc-dashboard"

# ──────────────────────────────────────────────────────────────
sep "CONNECTIVITY CHECKS"
echo "--- Graph API ---"
curl -so /dev/null -w "HTTP %{http_code} (%{time_total}s)\n" --max-time 10 https://graph.microsoft.com/v1.0/\\\$metadata 2>/dev/null || echo "FAILED (cannot reach graph.microsoft.com)"
echo "--- Log Analytics ---"
curl -so /dev/null -w "HTTP %{http_code} (%{time_total}s)\n" --max-time 10 https://api.loganalytics.io/ 2>/dev/null || echo "FAILED (cannot reach api.loganalytics.io)"
echo "--- Local gunicorn ---"
curl -so /dev/null -w "HTTP %{http_code} (%{time_total}s)\n" --max-time 5 http://127.0.0.1:5000/login 2>/dev/null || echo "FAILED (gunicorn not responding on :5000)"
echo "--- Local nginx (HTTP) ---"
curl -so /dev/null -w "HTTP %{http_code} (%{time_total}s)\n" --max-time 5 http://127.0.0.1/ 2>/dev/null || echo "FAILED or not configured"
echo "--- Local nginx (HTTPS) ---"
curl -kso /dev/null -w "HTTP %{http_code} (%{time_total}s)\n" --max-time 5 https://127.0.0.1/ 2>/dev/null || echo "FAILED or not configured"
echo ""

# ──────────────────────────────────────────────────────────────
sep "QUICK HEALTH SUMMARY"
echo ""
issues=0

# Check gunicorn
if ! ps aux | grep -q '[g]unicorn'; then
    echo "  ❌ Gunicorn is NOT running"
    issues=\$((issues + 1))
else
    echo "  ✅ Gunicorn running"
fi

# Check nginx
if command -v nginx &>/dev/null && systemctl is-active nginx &>/dev/null; then
    echo "  ✅ Nginx active"
else
    echo "  ⚠️  Nginx not active (may not be needed if no reverse proxy)"
fi

# Check DB exists and has data
if [ -n "\$DB_FILE" ] && [ -f "\$DB_FILE" ] && command -v sqlite3 &>/dev/null; then
    inc_count=\$(sqlite3 "\$DB_FILE" "SELECT count(*) FROM incidents;" 2>/dev/null || echo "0")
    if [ "\$inc_count" = "0" ]; then
        echo "  ⚠️  Database has 0 incidents — data fetch may have failed"
        issues=\$((issues + 1))
    else
        echo "  ✅ Database has \$inc_count incidents"
    fi
else
    echo "  ❌ Database not found or sqlite3 not installed"
    issues=\$((issues + 1))
fi

# Check .env
if [ -z "\$ENV_FILE" ]; then
    echo "  ❌ No .env file found — app cannot authenticate"
    issues=\$((issues + 1))
else
    echo "  ✅ .env exists"
fi

# Check for 'no URI read' errors
if [ "\${URI_ERRORS:-0}" -gt 0 ] || [ "\${JOURNAL_URI:-0}" -gt 0 ]; then
    echo "  ⚠️  'no URI read' errors detected — likely proxy_protocol mismatch (see PROXY PROTOCOL DIAGNOSIS above)"
    issues=\$((issues + 1))
fi

# Check Graph credentials configured
if [ -n "\$ENV_FILE" ]; then
    for key in CLIENT_ID TENANT_ID; do
        val=\$(grep "^\${key}=" "\$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
        if [ -z "\$val" ] || echo "\$val" | grep -qiE 'your[-_]|placeholder|changeme|xxx'; then
            echo "  ❌ \$key not configured — API calls will fail"
            issues=\$((issues + 1))
        fi
    done
fi

echo ""
if [ "\$issues" -eq 0 ]; then
    echo "  🎉 No obvious issues found"
else
    echo "  Found \$issues potential issue(s) — review sections above for details"
fi

sep "END OF COLLECTION"
echo "Collected at: \$(date -Iseconds)"
"@

# ── Generate standalone bash mode ─────────────────────────────
$accessFlag = if ($All) { "1" } else { "0" }
$finalScript = $remoteScript -replace '__LINES__', $Lines -replace '__ACCESS__', $accessFlag

if ($GenerateBash) {
    Write-Output $finalScript
    return
}

# ── Validate hosts ───────────────────────────────────────────
if (-not $Hosts -or $Hosts.Count -eq 0) {
    Write-Host ""
    Write-Host "  Usage: .\scripts\collect_remote_logs.ps1 -Hosts 'user@hostname'" -ForegroundColor Yellow
    Write-Host "         .\scripts\collect_remote_logs.ps1 -Hosts 'root@10.0.0.5','root@10.0.0.6'" -ForegroundColor Yellow
    Write-Host "         .\scripts\collect_remote_logs.ps1 -GenerateBash > collect.sh  (for manual run)" -ForegroundColor Yellow
    Write-Host ""
    Write-Error "No -Hosts specified. Provide one or more SSH targets (user@host)."
    return
}

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# ── Collect from each host ───────────────────────────────────
foreach ($target in $Hosts) {
    $hostLabel = $target -replace '[^a-zA-Z0-9\.\-]', '_'
    $outFile = Join-Path $outDir "${timestamp}_${hostLabel}.log"

    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Collecting from: $target (port $SshPort)" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

    # Pipe the script via stdin to avoid quoting hell
    $finalScript | ssh -p $SshPort -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new $target 'bash -s' 2>&1 | Tee-Object -FilePath $outFile

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "  ✅ Saved to: $outFile" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  ❌ SSH failed (exit $LASTEXITCODE) — partial output may be in: $outFile" -ForegroundColor Red
    }
}

# ── Summary ──────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Collection complete — files in: $outDir" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Get-ChildItem $outDir -Filter "${timestamp}_*" | ForEach-Object {
    Write-Host "  $($_.Name)  ($([math]::Round($_.Length / 1KB, 1)) KB)"
}
