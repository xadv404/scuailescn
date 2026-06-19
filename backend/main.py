"""
SQL Audit Scanner - FastAPI application (v5 — pipeline orchestration)
"""
import asyncio
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
from backend.reporter.report_generator import ReportGenerator
from backend.scanner.scan_pipeline import run_audit_pipeline
from backend.scanner.sqlmap_runner import SQLMapRunner
from backend.scanner.analyzer import ResultAnalyzer
from backend.scanner.core.scorer import calculate_risk_score as _legacy_score
from backend.utils.logger import setup_logger
from backend.utils.validators import validate_scan_config, validate_urls

logger = setup_logger("main", LOGS_DIR / "app.log")

# ── FastAPI app ────────────────────────────────────────────────
app = FastAPI(
    title="SQL Audit Scanner",
    description="Professional Security Audit Tool – local use only",
    version="5.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_runner   = SQLMapRunner()
_analyzer = ResultAnalyzer()
_reporter = ReportGenerator()

# In-memory scan registry
_scans: Dict[str, Dict[str, Any]] = {}


# ── Request schemas ────────────────────────────────────────────
class ScanRequest(BaseModel):
    urls: List[str]
    scan_type: str = "full_scan"          # "full_scan" | "deep_scan"
    scan_config: Optional[Dict[str, Any]] = None


# ── Background task — Full Scan (pipeline only) ────────────────
async def _run_full_scan(scan_id: str, url: str, config: Dict[str, Any]) -> None:
    start = datetime.now()

    def _upd(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    def _progress(msg: str, done: int, total: int) -> None:
        pct = min(85, done)  # pipeline reports done as actual pct
        _upd(progress=msg, progress_pct=pct)

    try:
        _upd(status="running", progress="Démarrage du pipeline…", progress_pct=5)
        logger.info(f"[{scan_id}] Full Scan started → {url}")

        pipeline_result = await run_audit_pipeline(
            url=url,
            config=config,
            progress_callback=_progress,
            timeout_per_phase=120,
        )

        end = datetime.now()
        _upd(progress="Génération du rapport…", progress_pct=90)

        report = _reporter.generate(
            scan_id=scan_id,
            url=url,
            pipeline_result=pipeline_result,
            status="completed",
            start_time=start,
            end_time=end,
            scan_config=config,
            scan_type="full_scan",
        )

        _upd(status="completed", report=report, progress="Terminé", progress_pct=100)
        logger.info(
            f"[{scan_id}] Completed — {len(pipeline_result['findings'])} finding(s) "
            f"— score={pipeline_result['risk_score']} level={pipeline_result['risk_level']}"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal error: {exc}", exc_info=True)
        _upd(status="failed", error=str(exc), progress_pct=0)
        _reporter.generate_error(
            scan_id=scan_id, url=url, error=str(exc),
            start_time=start, end_time=end, scan_config=config,
        )


# ── Background task — Deep Scan (pipeline + SQLMap) ───────────
async def _run_deep_scan(scan_id: str, url: str, config: Dict[str, Any]) -> None:
    start = datetime.now()

    def _upd(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    def _progress(msg: str, done: int, total: int) -> None:
        # Pipeline takes 5-60%; SQLMap takes 60-90%
        pct = 5 + round((min(done, 100) / 100) * 55)
        _upd(progress=msg, progress_pct=pct)

    try:
        _upd(status="running", progress="Démarrage analyse approfondie…", progress_pct=5)
        logger.info(f"[{scan_id}] Deep Scan started → {url}")

        # Run pipeline and SQLMap concurrently
        results = await asyncio.gather(
            run_audit_pipeline(url=url, config=config, progress_callback=_progress),
            _runner.run_scan(url, scan_id, config=config),
            return_exceptions=True,
        )

        pipeline_result: Dict[str, Any] = (
            results[0] if isinstance(results[0], dict)
            else {"findings": [], "risk_score": 0, "risk_level": "NONE",
                  "summary": {}, "recommendations": [], "phases": [],
                  "technologies": [], "database_type": None, "duration_s": 0}
        )
        sqlmap_result: Dict[str, Any] = (
            results[1] if isinstance(results[1], dict)
            else {"success": False, "error": str(results[1])}
        )

        # Merge SQLMap findings into pipeline findings
        if sqlmap_result.get("success"):
            raw_stdout = sqlmap_result.get("stdout", "")
            raw_dir    = sqlmap_result.get("output_dir", "")
            sql_finds  = _analyzer.merge(
                _analyzer.analyze(raw_stdout, url),
                _analyzer.analyze_from_dir(raw_dir, url),
            )
            db_type = _analyzer.detect_database_type(raw_stdout)
            if db_type and not pipeline_result.get("database_type"):
                pipeline_result["database_type"] = db_type

            # Merge without duplicates
            existing_names = {f.get("name", f.get("type")) for f in pipeline_result["findings"]}
            for sf in sql_finds:
                key = sf.get("name") or sf.get("type")
                if key not in existing_names:
                    pipeline_result["findings"].append(sf)
                    existing_names.add(key)
        else:
            if sqlmap_result.get("error"):
                logger.warning(f"[{scan_id}] SQLMap error: {sqlmap_result['error']}")

        end = datetime.now()
        _upd(progress="Génération du rapport…", progress_pct=92)

        report = _reporter.generate(
            scan_id=scan_id,
            url=url,
            pipeline_result=pipeline_result,
            status="completed",
            start_time=start,
            end_time=end,
            scan_config=config,
            scan_type="deep_scan",
        )

        _upd(status="completed", report=report, progress="Terminé", progress_pct=100)
        logger.info(
            f"[{scan_id}] Deep Scan completed — "
            f"{len(pipeline_result['findings'])} finding(s)"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal error: {exc}", exc_info=True)
        _upd(status="failed", error=str(exc), progress_pct=0)
        _reporter.generate_error(
            scan_id=scan_id, url=url, error=str(exc),
            start_time=start, end_time=end, scan_config=config,
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
        "version":          "5.0.0",
    }


@app.get("/api/config/defaults")
async def get_default_config():
    return SCAN_DEFAULT_CONFIG


@app.post("/api/scan/start", status_code=202)
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    ok_urls, url_errors = validate_urls(req.urls)
    if not ok_urls:
        raise HTTPException(status_code=422, detail={"validation_errors": url_errors})

    cfg = dict(req.scan_config or {})
    if cfg:
        ok_cfg, cfg_errors = validate_scan_config(cfg)
        if not ok_cfg:
            raise HTTPException(status_code=422, detail={"config_errors": cfg_errors})

    scan_type = req.scan_type if req.scan_type in ("full_scan", "deep_scan") else "full_scan"
    task_fn   = _run_deep_scan if scan_type == "deep_scan" else _run_full_scan

    ids = []
    for url in ok_urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id":      sid,
            "url":          url,
            "scan_type":    scan_type,
            "status":       "pending",
            "progress":     "En file d'attente",
            "progress_pct": 0,
            "started_at":   datetime.now().isoformat(),
            "report":       None,
            "error":        None,
        }
        bg.add_task(task_fn, sid, url, cfg)
        ids.append(sid)
        logger.info(f"Queued {scan_type} {sid} → {url}")

    return {"scan_ids": ids, "queued": len(ids), "scan_type": scan_type}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    if scan_id in _scans:
        s   = _scans[scan_id]
        rep = s.get("report") or {}
        return {
            "scan_id":      scan_id,
            "status":       s["status"],
            "scan_type":    s.get("scan_type", "full_scan"),
            "progress":     s.get("progress"),
            "progress_pct": s.get("progress_pct", 0),
            "url":          s["url"],
            "error":        s.get("error"),
            "summary":      rep.get("summary") if rep else None,
        }

    report = _reporter.load(scan_id)
    if report:
        return {
            "scan_id":      scan_id,
            "status":       report["status"],
            "scan_type":    report.get("scan_type", "full_scan"),
            "progress":     "Terminé",
            "progress_pct": 100,
            "url":          report["target"],
            "error":        report.get("error"),
            "summary":      report.get("summary"),
        }

    raise HTTPException(status_code=404, detail="Scan introuvable")


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    if scan_id in _scans and _scans[scan_id].get("report"):
        return _scans[scan_id]["report"]

    report = _reporter.load(scan_id)
    if report:
        return report

    raise HTTPException(status_code=404, detail="Rapport introuvable")


@app.get("/api/reports")
async def list_reports():
    return _reporter.list_all()


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
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
