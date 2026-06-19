#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SQL Audit Scanner – Installation script (Linux)
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

# ── 1. Python 3.10+ ──────────────────────────────────────────
info "Checking Python version…"
if ! command -v python3 &>/dev/null; then
  error "python3 not found. Please install Python 3.10 or later."
  exit 1
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Found Python $PY_VER"
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  info "Python version OK"
else
  error "Python 3.10+ required (found $PY_VER)"
  exit 1
fi

# ── 2. pip ────────────────────────────────────────────────────
info "Ensuring pip is up to date…"
python3 -m pip install --upgrade pip -q

# ── 3. Virtual environment ────────────────────────────────────
if [ ! -d ".venv" ]; then
  info "Creating virtual environment .venv …"
  python3 -m venv .venv
fi
info "Activating virtual environment…"
# shellcheck source=/dev/null
source .venv/bin/activate

# ── 4. Python dependencies ────────────────────────────────────
info "Installing Python dependencies…"
pip install -r requirements.txt -q
info "Python dependencies installed."

# ── 5. SQLMap ────────────────────────────────────────────────
info "Checking for SQLMap…"
if command -v sqlmap &>/dev/null; then
  info "SQLMap found: $(sqlmap --version 2>/dev/null | head -1)"
else
  warn "SQLMap not found in PATH. Attempting installation…"
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y sqlmap -qq
    info "SQLMap installed via apt."
  elif command -v pip3 &>/dev/null; then
    pip install sqlmap -q
    info "SQLMap installed via pip."
  else
    warn "Could not install SQLMap automatically."
    warn "Please install it manually: https://sqlmap.org"
    warn "Or set the SQLMAP_PATH environment variable to point to the sqlmap binary."
  fi
fi

# ── 6. Directory structure ────────────────────────────────────
info "Creating required directories…"
mkdir -p reports logs temp

# ── 7. Permissions ────────────────────────────────────────────
chmod +x run.sh 2>/dev/null || true

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Run the application:  ./run.sh"
echo "  Or manually:          source .venv/bin/activate && python3 run.py"
echo ""
echo "  The UI will be available at:  http://127.0.0.1:8000"
echo ""
