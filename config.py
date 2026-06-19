"""
SQL Audit Scanner - Configuration
"""
import os
from pathlib import Path

BASE_DIR     = Path(__file__).parent.resolve()
REPORTS_DIR  = BASE_DIR / "reports"
LOGS_DIR     = BASE_DIR / "logs"
TEMP_DIR     = BASE_DIR / "temp"
FRONTEND_DIR = BASE_DIR / "frontend"

# Report sub-directories
REPORTS_VULNS_DIR    = REPORTS_DIR / "vulnerabilities"
REPORTS_EVIDENCE_DIR = REPORTS_DIR / "evidence"
REPORTS_DATABASE_DIR = REPORTS_DIR / "database_results"
REPORTS_CSV_DIR      = REPORTS_DIR / "csv"

EXTRACTION_DIR = REPORTS_DATABASE_DIR  # backward compat

# ── SQLMap binary ──────────────────────────────────────────────
SQLMAP_PATH    = os.environ.get("SQLMAP_PATH", "sqlmap")
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "600"))

# ── FastAPI server ─────────────────────────────────────────────
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# ── Default scan configuration ─────────────────────────────────
SCAN_DEFAULT_CONFIG: dict = {
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "headers":    {},
    "cookies":    "",
    "auth_bearer": "",
    "timeout":    30,
    "threads":    5,
    "level":      3,
    "risk":       2,
    "techniques": "BEUSTQ",
    "test_forms": True,
    "smart_mode": False,
}

# ── Pipeline automatique ───────────────────────────────────────
# Mode agent de pentest : détection + extraction + CSV
ALLOW_EXTRACTION_MODE = True

# Fichier cibles (une URL par ligne, # = commentaire)
TARGETS_FILE = BASE_DIR / "targets.txt"

# ── Directory bootstrap ────────────────────────────────────────
for _d in (
    REPORTS_DIR, LOGS_DIR, TEMP_DIR,
    REPORTS_VULNS_DIR, REPORTS_EVIDENCE_DIR,
    REPORTS_DATABASE_DIR, REPORTS_CSV_DIR,
):
    _d.mkdir(parents=True, exist_ok=True)
