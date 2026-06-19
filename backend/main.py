"""
SQL Audit Scanner - FastAPI application entry point
"""
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import FRONTEND_DIR, LOGS_DIR, SCAN_DEFAULT_CONFIG
from backend.scanner.analyzer import ResultAnalyzer
from backend.scanner.reporter import ReportGenerator
from backend.scanner.sqlmap_runner import SQLMapRunner
from backend.utils.logger import setup_logger
from backend.utils.validators import validate_scan_config, validate_urls

logger = setup_logger("main", LOGS_DIR / "app.log")

# ── FastAPI app ────────────────────────────────────────────────
app = FastAPI(
    title="SQL Audit Scanner",
    description="Professional SQL Injection Audit Tool – local use only",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton service objects
_runner   = SQLMapRunner()
_analyzer = ResultAnalyzer()
_reporter = ReportGenerator()

# In-memory scan registry  {scan_id: {...}}
_scans: Dict[str, Dict[str, Any]] = {}


# ── Request schemas ────────────────────────────────────────────
class ScanRequest(BaseModel):
    urls: List[str]
    scan_config: Optional[Dict[str, Any]] = None


# ── Background task ────────────────────────────────────────────
async def _run_scan(scan_id: str, url: str, config: Dict[str, Any]) -> None:
    start = datetime.now()

    def _upd(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    try:
        _upd(status="running", progress="Initialisation de SQLMap…")
        logger.info(f"[{scan_id}] Scan started → {url}")

        _upd(progress="Tests d'injection SQL en cours…")
        result = await _runner.run_scan(url, scan_id, config=config)
        end = datetime.now()

        if not result["success"]:
            _upd(status="failed", error=result.get("error", "Erreur inconnue"))
            _reporter.generate(
                scan_id=scan_id, url=url, findings=[], status="failed",
                start_time=start, end_time=end,
                error=result.get("error"), scan_config=config,
            )
            return

        _upd(progress="Analyse des résultats…")
        raw_stdout = result.get("stdout", "")
        raw_dir    = result.get("output_dir", "")

        stdout_findings = _analyzer.analyze(raw_stdout, url)
        dir_findings    = _analyzer.analyze_from_dir(raw_dir, url)
        findings        = _analyzer.merge(stdout_findings, dir_findings)

        # Detect database engine from combined output
        combined_text   = raw_stdout
        database_type   = _analyzer.detect_database_type(combined_text)

        # Build scan_summary with full statistics
        from backend.scanner.reporter import _SEVERITY_ORDER
        sev_count = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in sev_count:
                sev_count[sev] += 1
        risk_level  = "NONE"
        for lvl in _SEVERITY_ORDER:
            if sev_count[lvl] > 0:
                risk_level = lvl.upper()
                break

        scan_summary = _analyzer.build_scan_summary(findings, database_type, risk_level)

        _upd(progress="Génération du rapport…")
        report = _reporter.generate(
            scan_id=scan_id, url=url, findings=findings, status="completed",
            start_time=start, end_time=end,
            scan_config=config, scan_summary=scan_summary, database_type=database_type,
        )
        _upd(status="completed", report=report, progress="Terminé")
        logger.info(
            f"[{scan_id}] Completed — {len(findings)} finding(s) — "
            f"risk={scan_summary['risk_level']} — db={database_type or 'unknown'}"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal error: {exc}", exc_info=True)
        _upd(status="failed", error=str(exc))
        _reporter.generate(
            scan_id=scan_id, url=url, findings=[], status="failed",
            start_time=start, end_time=end, error=str(exc), scan_config=config,
        )
    finally:
        _runner.cleanup(scan_id)


# ── API routes ─────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    import shutil as _shutil
    return {
        "status":           "ok",
        "sqlmap_available": _shutil.which("sqlmap") is not None,
        "active_scans":     len([s for s in _scans.values() if s["status"] == "running"]),
        "version":          "2.0.0",
    }


@app.get("/api/config/defaults")
async def get_default_config():
    """Return the default scan configuration (for UI pre-fill)."""
    return SCAN_DEFAULT_CONFIG


@app.post("/api/scan/start", status_code=202)
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    """Queue one scan per URL with optional custom configuration."""
    # Validate URLs
    ok_urls, url_errors = validate_urls(req.urls)
    if not ok_urls:
        raise HTTPException(status_code=422, detail={"validation_errors": url_errors})

    # Validate scan config if provided
    cfg = dict(req.scan_config or {})
    if cfg:
        ok_cfg, cfg_errors = validate_scan_config(cfg)
        if not ok_cfg:
            raise HTTPException(status_code=422, detail={"config_errors": cfg_errors})

    ids = []
    for url in req.urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id":    sid,
            "url":        url,
            "status":     "pending",
            "progress":   "En file d'attente",
            "started_at": datetime.now().isoformat(),
            "report":     None,
            "error":      None,
        }
        bg.add_task(_run_scan, sid, url, cfg)
        ids.append(sid)
        logger.info(f"Queued scan {sid} → {url}")

    return {"scan_ids": ids, "queued": len(ids)}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """Return live status for a running or completed scan."""
    if scan_id in _scans:
        s = _scans[scan_id]
        rep = s.get("report") or {}
        return {
            "scan_id":  scan_id,
            "status":   s["status"],
            "progress": s.get("progress"),
            "url":      s["url"],
            "error":    s.get("error"),
            "summary":  rep.get("summary") if rep else None,
        }

    report = _reporter.load(scan_id)
    if report:
        return {
            "scan_id":  scan_id,
            "status":   report["status"],
            "progress": "Terminé",
            "url":      report["target"],
            "error":    report.get("error"),
            "summary":  report.get("summary"),
        }

    raise HTTPException(status_code=404, detail="Scan introuvable")


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Return the full JSON report for a completed scan."""
    if scan_id in _scans and _scans[scan_id].get("report"):
        return _scans[scan_id]["report"]

    report = _reporter.load(scan_id)
    if report:
        return report

    raise HTTPException(status_code=404, detail="Rapport introuvable")


@app.get("/api/reports")
async def list_reports():
    """List all saved reports, newest first."""
    return _reporter.list_all()


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Remove a scan from memory and delete its report file."""
    removed_mem  = scan_id in _scans
    if removed_mem:
        del _scans[scan_id]
    removed_file = _reporter.delete(scan_id)
    if not removed_mem and not removed_file:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"deleted": scan_id}


# ── Serve frontend ─────────────────────────────────────────────
_static_dir = FRONTEND_DIR / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"error": "Frontend introuvable"}, status_code=404)


@app.get("/{full_path:path}", include_in_schema=False)
async def catch_all(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    raise HTTPException(status_code=404)
