#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SQL Audit Scanner – Installation script (Ubuntu / Debian VPS)
#  Usage : bash install.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║       SQL Audit Scanner – Install        ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── 1. Paquets système ────────────────────────────────────────
info "Installation des paquets système (apt)…"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git sqlmap
info "Paquets installés."

# ── 2. Python 3.10+ ──────────────────────────────────────────
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python $PY_VER détecté."
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  error "Python 3.10+ requis (trouvé $PY_VER)."
  exit 1
fi

# ── 3. Environnement virtuel ──────────────────────────────────
if [ ! -d ".venv" ]; then
  info "Création du venv…"
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate

# ── 4. Dépendances Python ─────────────────────────────────────
info "Installation des dépendances Python…"
pip install --upgrade pip -q
pip install -r requirements.txt -q
info "Dépendances Python installées."

# ── 5. Répertoires ────────────────────────────────────────────
mkdir -p reports logs temp
chmod +x run.sh

# ── 6. Service systemd (optionnel) ────────────────────────────
INSTALL_DIR="$SCRIPT_DIR"
SERVICE_FILE="/etc/systemd/system/scuailescn.service"

info "Création du service systemd dans $SERVICE_FILE…"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SQL Audit Scanner
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python3 ${INSTALL_DIR}/run.py
Restart=on-failure
RestartSec=5
Environment=HOST=0.0.0.0
Environment=PORT=9000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable scuailescn
systemctl restart scuailescn
info "Service démarré (systemctl status scuailescn)."

# ── Résumé ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation terminée !${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
IP=$(hostname -I | awk '{print $1}')
echo "  Scanner disponible sur :  http://${IP}:9000"
echo ""
echo "  Commandes utiles :"
echo "    systemctl status  scuailescn   # état"
echo "    systemctl restart scuailescn   # redémarrer"
echo "    journalctl -fu    scuailescn   # logs en direct"
echo ""
