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
apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx curl openssl

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
else
    # Merge any new keys from .env.example into existing .env
    echo "🔄 Checking for new config keys..."
    ADDED=0
    while IFS= read -r line; do
        # Skip comments, blank lines, and lines without KEY=VALUE
        [[ "$line" =~ ^[[:space:]]*#.*$ || -z "${line// /}" || ! "$line" =~ ^[A-Z_]+= ]] && continue
        KEY=$(echo "$line" | cut -d'=' -f1)
        if ! grep -q "^${KEY}=" "${CONF_DIR}/.env"; then
            echo "$line" >> "${CONF_DIR}/.env"
            echo "  ➕ Added new key: ${KEY}"
            ADDED=$((ADDED + 1))
        fi
    done < "${APP_DIR}/.env.example"
    if [ "$ADDED" -gt 0 ]; then
        echo "  ✅ Added ${ADDED} new key(s) to .env"
    else
        echo "  ✅ .env is up to date"
    fi
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
ln -sf /etc/nginx/sites-available/soc-dashboard /etc/nginx/sites-enabled/soc-dashboard
rm -f /etc/nginx/sites-enabled/default

# Auto-detect server name: use REDIRECT_URI domain if set, else LXC IP
SERVER_NAME="_"
if [ -f "${CONF_DIR}/.env" ]; then
    REDIR=$(grep -E "^REDIRECT_URI=" "${CONF_DIR}/.env" | cut -d'=' -f2- | sed 's|https\?://||;s|/.*||')
    if [ -n "$REDIR" ] && ! echo "$REDIR" | grep -qiE 'your-|yourdomain'; then
        SERVER_NAME="$REDIR"
    fi
fi
if [ "$SERVER_NAME" = "_" ]; then
    SERVER_NAME=$(hostname -I | awk '{print $1}')
fi
echo "  → server_name set to: ${SERVER_NAME}"

# ── 8b. Self-signed TLS (if no Let's Encrypt cert) ─
CERT_DIR="/etc/ssl/soc-dashboard"
if [ ! -d "/etc/letsencrypt/live/${SERVER_NAME}" ]; then
    echo "🔒 No Let's Encrypt cert found — generating self-signed certificate..."
    mkdir -p "${CERT_DIR}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERT_DIR}/selfsigned.key" \
        -out "${CERT_DIR}/selfsigned.crt" \
        -subj "/CN=${SERVER_NAME}" 2>/dev/null

    # Write complete nginx config with self-signed HTTPS
    cat > /etc/nginx/sites-available/soc-dashboard <<SSLEOF
# SOC Dashboard — nginx (auto-generated by deploy_lxc.sh)
# Self-signed TLS — replace with certbot for production:
#   certbot --nginx -d ${SERVER_NAME}

server {
    listen 80;
    listen [::]:80;
    server_name ${SERVER_NAME};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${SERVER_NAME};

    ssl_certificate     ${CERT_DIR}/selfsigned.crt;
    ssl_certificate_key ${CERT_DIR}/selfsigned.key;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location ~* \.(js|css|png|ico|svg|woff2?)$ {
        proxy_pass http://127.0.0.1:5000;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
SSLEOF
    echo "  ✅ Self-signed HTTPS + HTTP→HTTPS redirect configured"
else
    echo "  ✅ Let's Encrypt cert found — using template config"
    cp "${APP_DIR}/scripts/nginx_site.conf" /etc/nginx/sites-available/soc-dashboard
    sed -i "s/YOUR_DOMAIN/${SERVER_NAME}/g" /etc/nginx/sites-available/soc-dashboard
fi

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
# ── 10. Health check ─────────────────────────────
echo "🩺 Running health checks..."
HEALTH_OK=true
for SVC in dashboard nginx; do
    if systemctl is-active --quiet "${SVC}"; then
        echo "  ✅ ${SVC}: active"
    else
        echo "  ❌ ${SVC}: FAILED"
        HEALTH_OK=false
    fi
done
if systemctl is-active --quiet hourly-refresh.timer; then
    echo "  ✅ hourly-refresh.timer: active"
else
    echo "  ❌ hourly-refresh.timer: FAILED"
    HEALTH_OK=false
fi

# Test HTTPS endpoint
HTTPS_CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/ 2>/dev/null || echo "000")
if [ "$HTTPS_CODE" = "302" ] || [ "$HTTPS_CODE" = "200" ]; then
    echo "  ✅ HTTPS responding: ${HTTPS_CODE}"
else
    echo "  ⚠️  HTTPS returned: ${HTTPS_CODE} (may need .env credentials)"
fi

if [ "$HEALTH_OK" = true ]; then
    echo ""
    echo "🎉 All services healthy!"
fi

if [ "$ENV_OK" = false ]; then
    echo ""
    echo "⚠️  NEXT STEPS:"
    echo "  1. Edit ${CONF_DIR}/.env with real credentials"
    echo "  2. systemctl restart dashboard"
fi
echo ""
echo "  For production TLS: certbot --nginx -d <YOUR_DOMAIN>"
echo "============================================="
