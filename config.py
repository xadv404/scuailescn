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

# Dedicated directory for future extraction reports (never mixed with audit)
EXTRACTION_DIR = REPORTS_DIR / "extraction"

# ── SQLMap binary ──────────────────────────────────────────────
SQLMAP_PATH    = os.environ.get("SQLMAP_PATH", "sqlmap")
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "300"))

# ── FastAPI server ─────────────────────────────────────────────
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))

# ── Default scan configuration ─────────────────────────────────
# All fields can be overridden per-request from the UI.
SCAN_DEFAULT_CONFIG: dict = {
    # HTTP identity
    "user_agent": "SQLAuditScanner/1.0 (Authorized Security Audit)",
    "headers":    {},      # dict {"Header-Name": "value"} or "Key: Val\nKey2: Val2"
    "cookies":    "",      # raw cookie string, e.g.  "session=abc; csrftoken=xyz"
    "auth_bearer": "",     # Authorization: Bearer <token>  (masked in logs/reports)

    # SQLMap engine parameters
    "timeout":    30,      # per-HTTP-request timeout (seconds)
    "threads":    3,       # parallel request threads (1–10)
    "level":      2,       # detection depth  1=basic … 5=full (kept ≤5 for audit)
    "risk":       1,       # payload risk     1=safe  … 2=medium  (3 disabled for audit)
    "techniques": "BEUSTQ",# detection families: B=boolean, E=error, U=union,
                           #   S=stacked, T=time, Q=out-of-band
    "test_forms": True,    # also crawl and test HTML forms on the page
    "smart_mode": True,    # skip non-injectable parameters early (faster scan)
}

# ── Extraction mode ────────────────────────────────────────────
# MUST remain False during normal audit operation.
# Setting True enables the DataExtractor module which can retrieve
# database content — only authorised in explicit written-consent engagements.
ALLOW_EXTRACTION_MODE = False

# ── Directory bootstrap ────────────────────────────────────────
for _d in (REPORTS_DIR, LOGS_DIR, TEMP_DIR, EXTRACTION_DIR):
    _d.mkdir(parents=True, exist_ok=True)
