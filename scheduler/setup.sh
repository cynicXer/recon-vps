#!/bin/bash
# setup.sh - Deploy the recon automation stack on the recon-box droplet
# Run as root on the Ubuntu 24.04 droplet after the Ansible playbook completes.
set -euo pipefail

INSTALL_DIR="/opt/recon/scheduler"
VENV_DIR="/opt/recon/venv"
LOG_FILE="/var/log/recon.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Recon Automation Setup ==="

# ---------------------------------------------------------------------------
# 1. Dependencies
# ---------------------------------------------------------------------------
echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    docker.io \
    docker-compose-plugin \
    python3 \
    python3-pip \
    python3-venv \
    curl

systemctl enable --now docker

# ---------------------------------------------------------------------------
# 2. Install directory
# ---------------------------------------------------------------------------
echo "[2/7] Installing files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}"/. "${INSTALL_DIR}/"
chmod 750 "${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# 3. Python virtual environment
# ---------------------------------------------------------------------------
echo "[3/7] Setting up Python virtual environment..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"

# ---------------------------------------------------------------------------
# 4. Environment file with generated passwords
# ---------------------------------------------------------------------------
ENV_FILE="${INSTALL_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
    echo "[4/7] .env already exists, skipping password generation"
else
    echo "[4/7] Generating credentials..."
    POSTGRES_PASSWORD="$(openssl rand -hex 32)"
    GRAFANA_PASSWORD="$(openssl rand -hex 16)"

    cat > "${ENV_FILE}" <<EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}
# DB_PASSWORD is read by recon_runner.py at runtime
DB_PASSWORD=${POSTGRES_PASSWORD}
EOF
    chmod 600 "${ENV_FILE}"

    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │  Grafana admin password: ${GRAFANA_PASSWORD}  │"
    echo "  │  (also stored in ${ENV_FILE})               │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""
fi

# ---------------------------------------------------------------------------
# 5. Start Docker Compose stack
# ---------------------------------------------------------------------------
echo "[5/7] Starting PostgreSQL and Grafana..."
cd "${INSTALL_DIR}"
docker compose --env-file "${ENV_FILE}" up -d

echo "  Waiting for PostgreSQL to be healthy..."
for i in $(seq 1 30); do
    if docker compose exec -T postgres pg_isready -U recon -d recon > /dev/null 2>&1; then
        echo "  PostgreSQL is ready."
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: PostgreSQL did not become healthy in time."
        exit 1
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# 6. Touch log file
# ---------------------------------------------------------------------------
echo "[6/7] Setting up log file..."
touch "${LOG_FILE}"
chmod 640 "${LOG_FILE}"

# ---------------------------------------------------------------------------
# 7. Install cron job
# ---------------------------------------------------------------------------
echo "[7/7] Installing cron job..."
CRON_LINE="0 2 * * * DB_PASSWORD=\$(grep DB_PASSWORD ${ENV_FILE} | cut -d= -f2) ${VENV_DIR}/bin/python ${INSTALL_DIR}/recon_runner.py --all --config ${INSTALL_DIR}/config.yaml >> ${LOG_FILE} 2>&1"

# Add cron if not already present
if ! crontab -l 2>/dev/null | grep -q "recon_runner.py"; then
    (crontab -l 2>/dev/null; echo "${CRON_LINE}") | crontab -
    echo "  Cron job installed (runs daily at 02:00 UTC)"
else
    echo "  Cron job already present, skipping"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
DROPLET_IP="$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || echo '<droplet-ip>')"

echo ""
echo "=== Setup complete ==="
echo ""
echo "  Grafana:    http://${DROPLET_IP}:3000"
echo "              (user: admin, password in ${ENV_FILE})"
echo ""
echo "  Config:     ${INSTALL_DIR}/config.yaml"
echo "              -> Edit to set your target domains before the first run"
echo ""
echo "  Run now:    DB_PASSWORD=\$(grep DB_PASSWORD ${ENV_FILE} | cut -d= -f2) \\"
echo "              ${VENV_DIR}/bin/python ${INSTALL_DIR}/recon_runner.py --all"
echo ""
echo "  Logs:       tail -f ${LOG_FILE}"
echo ""
