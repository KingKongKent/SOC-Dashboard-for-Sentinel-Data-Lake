#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — Deploy to Ubuntu 24.04 LXC
# =============================================================
# Usage (from the Windows workspace):
#   scp -r ./*.py requirements.txt .env.example soc-dashboard-live.html static \
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
VENV_DIR="${APP_DIR}/venv"

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
mkdir -p "${APP_DIR}" "${DB_DIR}"
chown "${APP_USER}:${APP_USER}" "${DB_DIR}"

# ── 4. Python virtual environment ───────────────
echo "🐍 Creating Python virtual environment..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip -q
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" -q
"${VENV_DIR}/bin/pip" install gunicorn -q

# ── 5. .env file ────────────────────────────────
if [ ! -f "${APP_DIR}/.env" ]; then
    echo "⚠️  No .env found — copying template. Fill in credentials!"
    cp "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi
chmod 600 "${APP_DIR}/.env"
chown "${APP_USER}:${APP_USER}" "${APP_DIR}/.env"

# ── 5b. Validate required env vars ──────────────
echo "🔍 Checking .env for placeholder values..."
ENV_OK=true
for KEY in CLIENT_ID CLIENT_SECRET TENANT_ID SECRET_KEY REDIRECT_URI CORS_ORIGINS ADMIN_USERS; do
    VAL=$(grep -E "^${KEY}=" "${APP_DIR}/.env" | cut -d'=' -f2-)
    if [ -z "$VAL" ] || echo "$VAL" | grep -qiE 'your-|change-me|yourdomain'; then
        echo "  ⚠️  ${KEY} still has a placeholder value — update before starting the service"
        ENV_OK=false
    fi
done
if [ "$ENV_OK" = false ]; then
    echo "  → Edit ${APP_DIR}/.env with real values before proceeding"
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

echo ""
echo "============================================="
echo "✅ Deployment complete!"
echo "============================================="
echo "  App dir:    ${APP_DIR}"
echo "  DB dir:     ${DB_DIR}"
echo "  User:       ${APP_USER}"
echo "  Gunicorn:   systemctl status dashboard"
echo "  Scheduler:  systemctl list-timers hourly-refresh.timer"
echo "  Nginx:      systemctl status nginx"
echo ""
echo "⚠️  NEXT STEPS:"
echo "  1. Edit ${APP_DIR}/.env with real credentials"
echo "  2. Replace YOUR_DOMAIN in /etc/nginx/sites-available/soc-dashboard"
echo "     sed -i 's/YOUR_DOMAIN/your-actual-domain.com/g' /etc/nginx/sites-available/soc-dashboard"
echo "     nginx -t && systemctl reload nginx"
echo "  3. Run initial data fetch:"
echo "     sudo -u ${APP_USER} ${VENV_DIR}/bin/python ${APP_DIR}/fetch_live_data.py"
echo "  4. Set up DNS: <YOUR_DOMAIN> → <LXC_IP> (or proxy IP if using SNI routing)"
echo "  5. Run certbot: certbot --nginx -d <YOUR_DOMAIN>"
echo "============================================="
