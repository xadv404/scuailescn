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

# Report sub-directories (v3 multi-output structure)
REPORTS_VULNS_DIR    = REPORTS_DIR / "vulnerabilities"
REPORTS_EVIDENCE_DIR = REPORTS_DIR / "evidence"
REPORTS_DATABASE_DIR = REPORTS_DIR / "database_results"

# Extraction results (requires explicit authorisation)
EXTRACTION_DIR = REPORTS_DATABASE_DIR  # kept for backward compat

# ── SQLMap binary ──────────────────────────────────────────────
SQLMAP_PATH    = os.environ.get("SQLMAP_PATH", "sqlmap")
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "300"))

# ── FastAPI server ─────────────────────────────────────────────
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# ── Default scan configuration ─────────────────────────────────
SCAN_DEFAULT_CONFIG: dict = {
    "user_agent": "SQLAuditScanner/1.0 (Authorized Security Audit)",
    "headers":    {},
    "cookies":    "",
    "auth_bearer": "",
    "timeout":    30,
    "threads":    3,
    "level":      2,
    "risk":       1,
    "techniques": "BEUSTQ",
    "test_forms": True,
    "smart_mode": True,
}

# ── Extraction control ─────────────────────────────────────────
# Data row extraction is NEVER allowed without explicit authorisation.
# Deep scan may retrieve DB structure (tables/columns) but NOT row data.
ALLOW_EXTRACTION_MODE = False

# ── Directory bootstrap ────────────────────────────────────────
for _d in (
    REPORTS_DIR, LOGS_DIR, TEMP_DIR,
    REPORTS_VULNS_DIR, REPORTS_EVIDENCE_DIR, REPORTS_DATABASE_DIR,
):
    _d.mkdir(parents=True, exist_ok=True)
