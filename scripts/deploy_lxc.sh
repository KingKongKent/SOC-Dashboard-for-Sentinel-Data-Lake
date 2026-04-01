#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — Deploy to Ubuntu 24.04 LXC
# =============================================================
# FHS-compliant layout — works on LXCs with noexec /opt:
#
#   /opt/soc-dashboard/       — application code (read-only at runtime)
#   /usr/local/soc-venv/      — Python virtualenv (executables allowed)
#   /etc/soc-dashboard/       — .env config (secrets, owner socdash:600)
#   /var/lib/soc-dashboard/   — SQLite DB, encryption key, flask sessions
#   /var/log/soc-dashboard/   — gunicorn access & error logs
#
# Usage (from the Windows workspace):
#   scp -r ./*.py requirements.txt .env.example soc-dashboard-live.html setup.html static \
#       root@<YOUR_LXC_IP>:/opt/soc-dashboard/
#   scp -r scripts root@<YOUR_LXC_IP>:/opt/soc-dashboard/
#   ssh root@<YOUR_LXC_IP> 'bash /opt/soc-dashboard/scripts/deploy_lxc.sh'
#
# OR run directly on the LXC after cloning / copying files.
# =============================================================

set -euo pipefail

APP_DIR="/opt/soc-dashboard"
APP_USER="socdash"
DB_DIR="/var/lib/soc-dashboard"
VENV_DIR="/usr/local/soc-venv"
CONF_DIR="/etc/soc-dashboard"
LOG_DIR="/var/log/soc-dashboard"

echo "============================================="
echo "🚀 SOC Dashboard — LXC Deployment"
echo "============================================="

# ── 1. System packages ──────────────────────────
echo "📦 Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx

# ── 2. Service user ─────────────────────────────
if ! id "${APP_USER}" &>/dev/null; then
    echo "👤 Creating service user: ${APP_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

# ── 3. Directory structure ──────────────────────
echo "📂 Setting up directories..."
mkdir -p "${APP_DIR}" "${DB_DIR}" "${CONF_DIR}" "${LOG_DIR}"
chown "${APP_USER}:${APP_USER}" "${DB_DIR}" "${CONF_DIR}" "${LOG_DIR}"

# ── 3b. Migrate from old layout (if upgrading) ─
if [ -d "${APP_DIR}/venv" ]; then
    echo "🔄 Old venv found at ${APP_DIR}/venv — will be replaced by ${VENV_DIR}"
fi
if [ -f "${APP_DIR}/.env" ] && [ ! -f "${CONF_DIR}/.env" ]; then
    echo "🔄 Migrating .env from ${APP_DIR}/.env → ${CONF_DIR}/.env"
    cp -p "${APP_DIR}/.env" "${CONF_DIR}/.env"
    mv "${APP_DIR}/.env" "${APP_DIR}/.env.migrated"
    echo "   ✅ Old .env backed up as ${APP_DIR}/.env.migrated"
fi

# ── 4. Python virtual environment ───────────────
echo "🐍 Creating Python virtual environment at ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip -q
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" -q
"${VENV_DIR}/bin/pip" install gunicorn -q

# Clean up old venv after new one is confirmed working
if [ -d "${APP_DIR}/venv" ]; then
    echo "🗑️  Removing old venv at ${APP_DIR}/venv"
    rm -rf "${APP_DIR}/venv"
fi

# ── 5. .env file ────────────────────────────────
if [ ! -f "${CONF_DIR}/.env" ]; then
    echo "⚠️  No .env found — copying template. Fill in credentials!"
    cp "${APP_DIR}/.env.example" "${CONF_DIR}/.env"
fi
chmod 600 "${CONF_DIR}/.env"
chown "${APP_USER}:${APP_USER}" "${CONF_DIR}/.env"

# ── 5b. Validate required env vars ──────────────
echo "🔍 Checking .env for placeholder values..."
ENV_OK=true
for KEY in CLIENT_ID CLIENT_SECRET TENANT_ID SECRET_KEY REDIRECT_URI CORS_ORIGINS ADMIN_USERS; do
    VAL=$(grep -E "^${KEY}=" "${CONF_DIR}/.env" | cut -d'=' -f2-)
    if [ -z "$VAL" ] || echo "$VAL" | grep -qiE 'your-|change-me|yourdomain'; then
        echo "  ⚠️  ${KEY} still has a placeholder value — update before starting the service"
        ENV_OK=false
    fi
done
if [ "$ENV_OK" = false ]; then
    echo "  → Edit ${CONF_DIR}/.env with real values before proceeding"
fi

# ── 6. Initialise database ──────────────────────
echo "💾 Initialising database..."
cd "${APP_DIR}"
sudo -u "${APP_USER}" DB_PATH="${DB_DIR}/soc_dashboard.db" "${VENV_DIR}/bin/python" database.py

# ── 7. Install systemd units ────────────────────
echo "⚙️  Installing systemd services..."
bash "${APP_DIR}/scripts/setup_systemd.sh"

# ── 8. Install nginx config ─────────────────────
echo "🌐 Installing nginx config..."
cp "${APP_DIR}/scripts/nginx_site.conf" /etc/nginx/sites-available/soc-dashboard
ln -sf /etc/nginx/sites-available/soc-dashboard /etc/nginx/sites-enabled/soc-dashboard
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ── 9. Logrotate ────────────────────────────────
echo "📋 Installing logrotate config..."
cat > /etc/logrotate.d/soc-dashboard <<'LOGROTATE'
/var/log/soc-dashboard/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 socdash socdash
    postrotate
        systemctl kill -s USR1 dashboard.service 2>/dev/null || true
    endscript
}
LOGROTATE

echo ""
echo "============================================="
echo "✅ Deployment complete!"
echo "============================================="
echo "  App dir:    ${APP_DIR}"
echo "  Venv:       ${VENV_DIR}"
echo "  Config:     ${CONF_DIR}/.env"
echo "  DB dir:     ${DB_DIR}"
echo "  Logs:       ${LOG_DIR}"
echo "  User:       ${APP_USER}"
echo "  Gunicorn:   systemctl status dashboard"
echo "  Scheduler:  systemctl list-timers hourly-refresh.timer"
echo "  Nginx:      systemctl status nginx"
echo ""
echo "⚠️  NEXT STEPS:"
echo "  1. Edit ${CONF_DIR}/.env with real credentials"
echo "  2. Replace YOUR_DOMAIN in /etc/nginx/sites-available/soc-dashboard"
echo "     sed -i 's/YOUR_DOMAIN/your-actual-domain.com/g' /etc/nginx/sites-available/soc-dashboard"
echo "     nginx -t && systemctl reload nginx"
echo "  3. Run initial data fetch:"
echo "     sudo -u ${APP_USER} ${VENV_DIR}/bin/python ${APP_DIR}/fetch_live_data.py"
echo "  4. Set up DNS: <YOUR_DOMAIN> → <LXC_IP> (or proxy IP if using SNI routing)"
echo "  5. Run certbot: certbot --nginx -d <YOUR_DOMAIN>"
echo "============================================="
