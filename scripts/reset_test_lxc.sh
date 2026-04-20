#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — Full Test LXC Reset
# =============================================================
# Wipes ALL state so each test cycle starts 100% clean:
#   • Stops all services
#   • Deletes DB, config key, sessions
#   • Resets .env to .env.example (placeholder values)
#   • Clears ALL journal logs for dashboard + hourly-refresh
#   • Truncates gunicorn log files
#   • Pulls latest code from origin/main
#   • Starts dashboard service (setup wizard ready)
#
# Usage (from Windows workspace):
#   ssh root@<LXC_IP> 'bash /opt/soc-dashboard/scripts/reset_test_lxc.sh'
#
# Or after pushing new code:
#   ssh root@<LXC_IP> 'cd /opt/soc-dashboard && git pull origin main && bash scripts/reset_test_lxc.sh'
# =============================================================

set -euo pipefail

APP_DIR="/opt/soc-dashboard"
DB_DIR="/var/lib/soc-dashboard"
CONF_DIR="/etc/soc-dashboard"
LOG_DIR="/var/log/soc-dashboard"
VENV_DIR="/usr/local/soc-venv"

echo "============================================="
echo "🔄 SOC Dashboard — Full Test Reset"
echo "============================================="

# ── 1. Stop everything ──────────────────────────
echo "⏹️  Stopping services..."
systemctl stop dashboard.service 2>/dev/null || true
systemctl stop hourly-refresh.timer 2>/dev/null || true
systemctl stop hourly-refresh.service 2>/dev/null || true
echo "   ✅ All services stopped"

# ── 2. Wipe application state ───────────────────
echo "🗑️  Wiping application state..."
rm -f  "${DB_DIR}/soc_dashboard.db"
rm -f  "${DB_DIR}/config.key"
rm -f  "${DB_DIR}/.encryption_key"
rm -rf "${DB_DIR}/flask_sessions"
mkdir -p "${DB_DIR}/flask_sessions"
chown socdash:socdash "${DB_DIR}/flask_sessions"
echo "   ✅ DB, config key, and sessions deleted"

# ── 3. Reset .env to example (placeholders) ─────
echo "📝 Resetting .env to placeholder values..."
if [ -f "${APP_DIR}/.env.example" ]; then
    cp "${APP_DIR}/.env.example" "${CONF_DIR}/.env"
    chown socdash:socdash "${CONF_DIR}/.env"
    chmod 600 "${CONF_DIR}/.env"
    echo "   ✅ .env reset from .env.example"
else
    echo "   ⚠️  No .env.example found — .env left as-is"
fi

# ── 4. Clear ALL logs ───────────────────────────
echo "📋 Clearing logs..."
# Journal logs for our units
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s -u dashboard.service 2>/dev/null || true
journalctl --vacuum-time=1s -u hourly-refresh.service 2>/dev/null || true
# Gunicorn file logs
for f in "${LOG_DIR}"/*.log; do
    [ -f "$f" ] && truncate -s 0 "$f"
done
# Gunicorn heartbeat dir
rm -rf "${DB_DIR}/.gunicorn"
echo "   ✅ Journal + file logs cleared"

# ── 5. Pull latest code ─────────────────────────
echo "📥 Pulling latest code..."
cd "${APP_DIR}"
git fetch origin main
git reset --hard origin/main
echo "   ✅ Code at $(git rev-parse --short HEAD)"

# ── 6. Update pip dependencies (if changed) ─────
echo "📦 Checking pip dependencies..."
"${VENV_DIR}/bin/pip" install -q -r "${APP_DIR}/requirements.txt" 2>&1 | tail -1 || true

# ── 7. Start dashboard (setup wizard mode) ──────
echo "🚀 Starting dashboard service..."
systemctl start dashboard.service
sleep 2

# ── 8. Verify ───────────────────────────────────
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/setup 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "   ✅ Setup wizard ready (HTTP 200)"
else
    echo "   ❌ Unexpected HTTP ${HTTP_CODE} — check: journalctl -u dashboard.service -n 20"
fi

echo ""
echo "============================================="
echo "✅ Reset complete — clean slate"
echo "============================================="
echo "  HEAD:    $(git log --oneline -1)"
echo "  DB:      (empty — will be created on first request)"
echo "  .env:    placeholder values (setup wizard will prompt)"
echo "  Logs:    cleared"
echo ""
echo "  Next: open http://<LXC_IP>:5000/setup in browser"
echo "============================================="
