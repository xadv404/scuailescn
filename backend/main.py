"""
SQL Audit Scanner - FastAPI application entry point
"""
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import FRONTEND_DIR, LOGS_DIR
from backend.scanner.analyzer import ResultAnalyzer
from backend.scanner.reporter import ReportGenerator
from backend.scanner.sqlmap_runner import SQLMapRunner
from backend.utils.logger import setup_logger
from backend.utils.validators import validate_urls

logger = setup_logger("main", LOGS_DIR / "app.log")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SQL Audit Scanner",
    description="Professional SQL Injection Audit Tool – local use only",
    version="1.0.0",
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


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    urls: List[str]


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------
async def _run_scan(scan_id: str, url: str) -> None:
    start = datetime.now()

    def _update(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    try:
        _update(status="running", progress="Initialising SQLMap…")
        logger.info(f"[{scan_id}] Scan started for {url}")

        _update(progress="Running SQL injection tests…")
        result = await _runner.run_scan(url, scan_id)
        end = datetime.now()

        if not result["success"]:
            _update(status="failed", error=result.get("error", "Unknown error"))
            _reporter.generate(
                scan_id=scan_id, url=url, findings=[], status="failed",
                start_time=start, end_time=end, error=result.get("error"),
            )
            return

        _update(progress="Analysing results…")
        stdout_findings = _analyzer.analyze(result.get("stdout", ""), url)
        dir_findings    = _analyzer.analyze_from_dir(result.get("output_dir", ""), url)
        findings        = _analyzer.merge(stdout_findings, dir_findings)

        _update(progress="Generating report…")
        report = _reporter.generate(
            scan_id=scan_id, url=url, findings=findings, status="completed",
            start_time=start, end_time=end,
        )
        _update(status="completed", report=report, progress="Done")
        logger.info(
            f"[{scan_id}] Completed – {len(findings)} finding(s), "
            f"risk={report['summary']['risk_level']}"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal error: {exc}", exc_info=True)
        _update(status="failed", error=str(exc))
        _reporter.generate(
            scan_id=scan_id, url=url, findings=[], status="failed",
            start_time=start, end_time=end, error=str(exc),
        )
    finally:
        _runner.cleanup(scan_id)


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    import shutil
    return {
        "status": "ok",
        "sqlmap_available": shutil.which("sqlmap") is not None,
        "active_scans": len([s for s in _scans.values() if s["status"] == "running"]),
    }


@app.post("/api/scan/start", status_code=202)
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    """Queue one scan per URL and return the scan IDs."""
    ok, errors = validate_urls(req.urls)
    if not ok:
        raise HTTPException(status_code=422, detail={"validation_errors": errors})

    ids = []
    for url in req.urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id": sid,
            "url": url,
            "status": "pending",
            "progress": "Queued",
            "started_at": datetime.now().isoformat(),
            "report": None,
            "error": None,
        }
        bg.add_task(_run_scan, sid, url)
        ids.append(sid)
        logger.info(f"Queued scan {sid} → {url}")

    return {"scan_ids": ids, "queued": len(ids)}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """Return live status for a running or completed scan."""
    if scan_id in _scans:
        s = _scans[scan_id]
        return {
            "scan_id": scan_id,
            "status": s["status"],
            "progress": s.get("progress"),
            "url": s["url"],
            "error": s.get("error"),
            # Only include report summary to keep response small
            "summary": s["report"]["summary"] if s.get("report") else None,
        }

    # Fall back to persisted report
    report = _reporter.load(scan_id)
    if report:
        return {
            "scan_id": scan_id,
            "status": report["status"],
            "progress": "Completed",
            "url": report["target"],
            "error": report.get("error"),
            "summary": report.get("summary"),
        }

    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Return the full JSON report for a scan."""
    # Try in-memory first (for still-running scans whose report is ready)
    if scan_id in _scans and _scans[scan_id].get("report"):
        return _scans[scan_id]["report"]

    report = _reporter.load(scan_id)
    if report:
        return report

    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/api/reports")
async def list_reports():
    """List all saved reports (newest first)."""
    return _reporter.list_all()


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Remove a scan from memory and delete its report file."""
    removed_memory = scan_id in _scans
    if removed_memory:
        del _scans[scan_id]
    removed_file = _reporter.delete(scan_id)
    if not removed_memory and not removed_file:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": scan_id}


# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------
_static_dir = FRONTEND_DIR / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"error": "Frontend not found"}, status_code=404)


@app.get("/{full_path:path}", include_in_schema=False)
async def catch_all(full_path: str):
    # SPA-style: everything that is not /api/* falls back to index.html
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    raise HTTPException(status_code=404)
