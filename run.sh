#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SQL Audit Scanner – Launch script
# ═══════════════════════════════════════════════════════════════
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV=".venv/bin/activate"
if [ -f "$VENV" ]; then
  # shellcheck source=/dev/null
  source "$VENV"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║        SQL Audit Scanner – Start         ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  URL : http://${HOST}:${PORT}"
echo "  Press Ctrl+C to stop."
echo ""

python3 run.py
