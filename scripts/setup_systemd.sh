#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — systemd service & timer setup
# =============================================================
# Creates:
#   dashboard.service   — gunicorn serving the Flask app
#   hourly-refresh.service + hourly-refresh.timer — scheduled data fetch
# =============================================================

set -euo pipefail

APP_DIR="/opt/soc-dashboard"
APP_USER="socdash"
DB_DIR="/var/lib/soc-dashboard"
VENV_DIR="${APP_DIR}/venv"
WORKERS=2

# ── Dashboard (gunicorn) service ────────────────
cat > /etc/systemd/system/dashboard.service <<EOF
[Unit]
Description=SOC Dashboard (gunicorn)
After=network.target

[Service]
Type=notify
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=PATH=${VENV_DIR}/bin:/usr/bin
EnvironmentFile=${APP_DIR}/.env
ExecStart=${VENV_DIR}/bin/gunicorn \
    --workers ${WORKERS} \
    --bind 127.0.0.1:5000 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    dashboard_backend:app
Restart=always
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DB_DIR}
ReadOnlyPaths=${APP_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ── Hourly refresh one-shot service ─────────────
cat > /etc/systemd/system/hourly-refresh.service <<EOF
[Unit]
Description=SOC Dashboard Hourly Data Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment=PATH=${VENV_DIR}/bin:/usr/bin
EnvironmentFile=${APP_DIR}/.env
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/append_data.py
TimeoutStartSec=600
StandardOutput=journal
StandardError=journal
EOF

# ── Hourly refresh timer ────────────────────────
cat > /etc/systemd/system/hourly-refresh.timer <<EOF
[Unit]
Description=SOC Dashboard Hourly Refresh Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
AccuracySec=1min
Unit=hourly-refresh.service

[Install]
WantedBy=timers.target
EOF

# ── Enable and start ────────────────────────────
systemctl daemon-reload
systemctl enable --now dashboard.service
systemctl enable --now hourly-refresh.timer

echo "✅ systemd units installed and started"
echo "   dashboard.service:      $(systemctl is-active dashboard.service)"
echo "   hourly-refresh.timer:   $(systemctl is-active hourly-refresh.timer)"
