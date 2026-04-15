#!/usr/bin/env bash
# =============================================================
# SOC Dashboard — Update / Install from Git
# =============================================================
# Pulls the latest code from GitHub into /opt/soc-dashboard.
#
# FRESH INSTALL:
#   bash <(curl -sL https://raw.githubusercontent.com/KingKongKent/SOC-Dashboard-for-Sentinel-Data-Lake/main/scripts/update_from_git.sh)
#   # Then run: bash /opt/soc-dashboard/scripts/deploy_lxc.sh
#
# UPDATE EXISTING:
#   bash /opt/soc-dashboard/scripts/update_from_git.sh
#   # Automatically restarts services if deploy_lxc.sh has been run before.
#
# OPTIONS:
#   --branch <name>     Checkout a specific branch (default: main)
#   --no-restart        Pull code but don't restart services
#   --full-deploy       Run deploy_lxc.sh after pulling (for dependency/config changes)
# =============================================================

set -euo pipefail

REPO_URL="https://github.com/KingKongKent/SOC-Dashboard-for-Sentinel-Data-Lake.git"
APP_DIR="/opt/soc-dashboard"
VENV_DIR="/usr/local/soc-venv"
BRANCH="main"
NO_RESTART=false
FULL_DEPLOY=false

# ── Parse arguments ─────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)  BRANCH="$2"; shift 2 ;;
        --no-restart)  NO_RESTART=true; shift ;;
        --full-deploy) FULL_DEPLOY=true; shift ;;
        *)  echo "❌ Unknown option: $1"; exit 1 ;;
    esac
done

echo "============================================="
echo "🔄 SOC Dashboard — Git Update"
echo "============================================="
echo "  Branch: ${BRANCH}"
echo "  Target: ${APP_DIR}"
echo ""

# ── Ensure git is installed ─────────────────────
if ! command -v git &>/dev/null; then
    echo "📦 Installing git..."
    apt-get update -qq && apt-get install -y -qq git
fi

# ── Clone or pull ───────────────────────────────
if [ ! -d "${APP_DIR}/.git" ]; then
    # Fresh install — clone the repo
    echo "📥 Cloning repository..."
    if [ -d "${APP_DIR}" ] && [ "$(ls -A ${APP_DIR} 2>/dev/null)" ]; then
        # Existing files from SCP deploy — back up and clone beside, then merge
        echo "  ⚠️  Existing files found in ${APP_DIR} (from manual deploy)"
        BACKUP_DIR="${APP_DIR}.pre-git-$(date +%Y%m%d%H%M%S)"
        echo "  → Backing up to ${BACKUP_DIR}"
        cp -a "${APP_DIR}" "${BACKUP_DIR}"

        # Clone into temp dir, then move .git in
        TMPDIR=$(mktemp -d)
        git clone --branch "${BRANCH}" --single-branch "${REPO_URL}" "${TMPDIR}"
        # Move .git into app dir (preserves existing .env, DB, etc.)
        mv "${TMPDIR}/.git" "${APP_DIR}/.git"
        rm -rf "${TMPDIR}"

        # Reset working tree to match repo (leaves untracked files like .env alone)
        cd "${APP_DIR}"
        git checkout "${BRANCH}" -- .
        git clean -fd --exclude='.env*' --exclude='*.db' --exclude='*.key'
        echo "  ✅ Repository initialised from existing install"
    else
        mkdir -p "$(dirname ${APP_DIR})"
        git clone --branch "${BRANCH}" --single-branch "${REPO_URL}" "${APP_DIR}"
        echo "  ✅ Cloned ${BRANCH} branch"
    fi
else
    # Existing git repo — pull latest
    cd "${APP_DIR}"
    CURRENT_BRANCH=$(git branch --show-current)

    # Stash any local changes (e.g. manual hotfixes)
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        echo "  ⚠️  Local changes detected — stashing"
        git stash push -m "auto-stash before update $(date +%Y%m%d-%H%M%S)"
    fi

    # Switch branch if needed
    if [ "${CURRENT_BRANCH}" != "${BRANCH}" ]; then
        echo "  🔀 Switching from ${CURRENT_BRANCH} to ${BRANCH}"
        git checkout "${BRANCH}"
    fi

    echo "📥 Pulling latest changes..."
    BEFORE=$(git rev-parse HEAD)
    git pull --ff-only origin "${BRANCH}"
    AFTER=$(git rev-parse HEAD)

    if [ "${BEFORE}" = "${AFTER}" ]; then
        echo "  ✅ Already up to date (${AFTER:0:8})"
        if [ "$FULL_DEPLOY" = false ] && [ "$NO_RESTART" = false ]; then
            echo "  → No changes to deploy. Use --full-deploy to force."
            exit 0
        fi
    else
        COUNT=$(git log --oneline "${BEFORE}..${AFTER}" | wc -l)
        echo "  ✅ Updated: ${BEFORE:0:8} → ${AFTER:0:8} (${COUNT} commit(s))"
        echo ""
        echo "  Recent changes:"
        git log --oneline --no-decorate "${BEFORE}..${AFTER}" | head -10 | sed 's/^/    /'
    fi
fi

echo ""

# ── Update pip dependencies if requirements changed ─
if [ -d "${VENV_DIR}" ]; then
    cd "${APP_DIR}"
    # Check if requirements.txt was modified in the pull
    if [ -n "${BEFORE:-}" ] && [ -n "${AFTER:-}" ] && [ "${BEFORE}" != "${AFTER}" ]; then
        if git diff --name-only "${BEFORE}" "${AFTER}" | grep -q 'requirements.txt'; then
            echo "📦 requirements.txt changed — updating dependencies..."
            "${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" -q
            echo "  ✅ Dependencies updated"
        fi
    fi
else
    echo "  ℹ️  No venv found — run deploy_lxc.sh for initial setup"
fi

# ── Full deploy or service restart ──────────────
if [ "$FULL_DEPLOY" = true ]; then
    echo ""
    echo "🚀 Running full deployment..."
    bash "${APP_DIR}/scripts/deploy_lxc.sh"
elif [ "$NO_RESTART" = false ] && systemctl is-active dashboard &>/dev/null; then
    echo ""
    echo "🔄 Restarting services..."
    systemctl restart dashboard
    sleep 2

    # Verify service health
    if systemctl is-active dashboard &>/dev/null; then
        echo "  ✅ dashboard: active"
    else
        echo "  ❌ dashboard: FAILED — check: journalctl -u dashboard -n 30"
        exit 1
    fi

    # Reload nginx if config changed
    if [ -n "${BEFORE:-}" ] && [ -n "${AFTER:-}" ] && [ "${BEFORE}" != "${AFTER}" ]; then
        if git diff --name-only "${BEFORE}" "${AFTER}" | grep -q 'nginx_site.conf'; then
            echo "  🌐 nginx config changed — validating..."
            if nginx -t 2>/dev/null; then
                systemctl reload nginx
                echo "  ✅ nginx reloaded"
            else
                echo "  ⚠️  nginx config invalid — NOT reloaded. Fix manually."
            fi
        fi
    fi

    echo ""
    echo "✅ Update complete!"
else
    echo ""
    echo "✅ Code updated. Services not restarted (--no-restart or not yet deployed)."
    if [ ! -f "/etc/systemd/system/dashboard.service" ]; then
        echo ""
        echo "  → First time? Run: bash ${APP_DIR}/scripts/deploy_lxc.sh"
    fi
fi
