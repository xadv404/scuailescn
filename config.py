"""
SQL Audit Scanner - Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()

REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR    = BASE_DIR / "logs"
TEMP_DIR    = BASE_DIR / "temp"
FRONTEND_DIR = BASE_DIR / "frontend"

# SQLMap binary path (override with env var SQLMAP_PATH if needed)
SQLMAP_PATH = os.environ.get("SQLMAP_PATH", "sqlmap")

# Max seconds before killing a sqlmap process
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "300"))

# FastAPI server
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# Ensure directories exist at import time
for _d in (REPORTS_DIR, LOGS_DIR, TEMP_DIR):
    _d.mkdir(parents=True, exist_ok=True)
