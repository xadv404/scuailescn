"""
SQL Audit Scanner - FastAPI application entry point
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
from backend.scanner.analyzer import ResultAnalyzer
from backend.scanner.core.scorer import calculate_risk_score
from backend.scanner.passive_scanner import run_passive_scan
from backend.scanner.reporter import ReportGenerator
from backend.scanner.sqlmap_runner import SQLMapRunner
from backend.utils.logger import setup_logger
from backend.utils.validators import validate_scan_config, validate_urls

logger = setup_logger("main", LOGS_DIR / "app.log")

# ── FastAPI app ────────────────────────────────────────────────
app = FastAPI(
    title="SQL Audit Scanner",
    description="Professional SQL Injection Audit Tool – local use only",
    version="3.0.0",
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


# ── Helpers ────────────────────────────────────────────────────

def _merge_all_findings(
    passive: List[Dict[str, Any]],
    sqlmap: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge passive + SQLMap findings, deduplicating by type."""
    merged   = list(passive)
    existing = {f["type"] for f in merged}
    for f in sqlmap:
        if f["type"] not in existing:
            merged.append(f)
            existing.add(f["type"])
    return merged


def _build_categories(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return per-category finding counts and severity breakdown."""
    cats: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        cat = f.get("category", "Général")
        sev = f.get("severity", "info")
        if cat not in cats:
            cats[cat] = {
                "count": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
        cats[cat]["count"] += 1
        if sev in cats[cat]["severity"]:
            cats[cat]["severity"][sev] += 1
    return cats


def _detect_technologies(
    passive_findings: List[Dict[str, Any]],
    database_type: Optional[str],
) -> List[str]:
    techs: List[str] = []
    if database_type:
        techs.append(database_type)
    for f in passive_findings:
        combined = (str(f.get("evidence", "")) + " " + str(f.get("description", ""))).lower()
        for tech, keywords in (
            ("PHP",       ("php",)),
            ("WordPress", ("wordpress", "wp-")),
            ("Nginx",     ("nginx",)),
            ("Apache",    ("apache",)),
            ("Node.js",   ("express", "node.js")),
            ("Django",    ("django",)),
            ("Laravel",   ("laravel",)),
        ):
            if any(kw in combined for kw in keywords) and tech not in techs:
                techs.append(tech)
    return techs


# ── Background task ────────────────────────────────────────────
async def _run_scan(scan_id: str, url: str, config: Dict[str, Any]) -> None:
    start = datetime.now()

    def _upd(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    try:
        _upd(status="running", progress="Initialisation des modules de détection…", progress_pct=5)
        logger.info(f"[{scan_id}] Scan started → {url}")

        # ── Progress callback for passive modules ──────────────
        _passive_total = 7  # number of passive modules

        def _passive_cb(module_name: str, done: int, total: int) -> None:
            pct = 5 + round((done / total) * 40)
            _upd(
                progress=f"Modules passifs : {done}/{total} ({module_name})…",
                progress_pct=pct,
            )

        # ── Run passive scan + SQLMap concurrently ─────────────
        _upd(progress="Analyse passive et SQLMap en parallèle…", progress_pct=10)

        gather_results = await asyncio.gather(
            run_passive_scan(url, config, _passive_cb),
            _runner.run_scan(url, scan_id, config=config),
            return_exceptions=True,
        )

        passive_findings: List[Dict[str, Any]] = (
            gather_results[0] if isinstance(gather_results[0], list) else []
        )
        sqlmap_result: Dict[str, Any] = (
            gather_results[1]
            if isinstance(gather_results[1], dict)
            else {"success": False, "error": str(gather_results[1])}
        )

        end = datetime.now()

        # ── Extract SQLMap findings ────────────────────────────
        database_type: Optional[str] = None
        if sqlmap_result.get("success"):
            raw_stdout      = sqlmap_result.get("stdout", "")
            raw_dir         = sqlmap_result.get("output_dir", "")
            stdout_findings = _analyzer.analyze(raw_stdout, url)
            dir_findings    = _analyzer.analyze_from_dir(raw_dir, url)
            sqlmap_findings = _analyzer.merge(stdout_findings, dir_findings)
            database_type   = _analyzer.detect_database_type(raw_stdout)
        else:
            sqlmap_findings = []
            if not sqlmap_result.get("success") and sqlmap_result.get("error"):
                logger.warning(f"[{scan_id}] SQLMap error: {sqlmap_result['error']}")

        _upd(progress="Analyse et consolidation des résultats…", progress_pct=80)

        all_findings = _merge_all_findings(passive_findings, sqlmap_findings)
        risk_score   = calculate_risk_score(all_findings)
        categories   = _build_categories(all_findings)
        technologies = _detect_technologies(passive_findings, database_type)

        # ── Build scan_summary ─────────────────────────────────
        from backend.scanner.reporter import _SEVERITY_ORDER
        sev_count = {s: 0 for s in _SEVERITY_ORDER}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in sev_count:
                sev_count[sev] += 1

        risk_level = "NONE"
        for lvl in _SEVERITY_ORDER:
            if sev_count[lvl] > 0:
                risk_level = lvl.upper()
                break

        scan_summary = _analyzer.build_scan_summary(all_findings, database_type, risk_level)
        scan_summary["risk_score"]   = risk_score
        scan_summary["categories"]   = categories
        scan_summary["technologies"] = technologies

        _upd(progress="Génération du rapport…", progress_pct=90)
        report = _reporter.generate(
            scan_id=scan_id,
            url=url,
            findings=all_findings,
            status="completed",
            start_time=start,
            end_time=end,
            scan_config=config,
            scan_summary=scan_summary,
            database_type=database_type,
            risk_score=risk_score,
            categories=categories,
            technologies=technologies,
        )
        _upd(status="completed", report=report, progress="Terminé", progress_pct=100)
        logger.info(
            f"[{scan_id}] Completed — {len(all_findings)} finding(s) — "
            f"risk={risk_level} score={risk_score} — db={database_type or 'unknown'}"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal error: {exc}", exc_info=True)
        _upd(status="failed", error=str(exc), progress_pct=0)
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
        "version":          "3.0.0",
    }


@app.get("/api/config/defaults")
async def get_default_config():
    """Return the default scan configuration (for UI pre-fill)."""
    return SCAN_DEFAULT_CONFIG


@app.post("/api/scan/start", status_code=202)
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    """Queue one scan per URL with optional custom configuration."""
    ok_urls, url_errors = validate_urls(req.urls)
    if not ok_urls:
        raise HTTPException(status_code=422, detail={"validation_errors": url_errors})

    cfg = dict(req.scan_config or {})
    if cfg:
        ok_cfg, cfg_errors = validate_scan_config(cfg)
        if not ok_cfg:
            raise HTTPException(status_code=422, detail={"config_errors": cfg_errors})

    ids = []
    for url in req.urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id":     sid,
            "url":         url,
            "status":      "pending",
            "progress":    "En file d'attente",
            "progress_pct": 0,
            "started_at":  datetime.now().isoformat(),
            "report":      None,
            "error":       None,
        }
        bg.add_task(_run_scan, sid, url, cfg)
        ids.append(sid)
        logger.info(f"Queued scan {sid} → {url}")

    return {"scan_ids": ids, "queued": len(ids)}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """Return live status for a running or completed scan."""
    if scan_id in _scans:
        s   = _scans[scan_id]
        rep = s.get("report") or {}
        return {
            "scan_id":      scan_id,
            "status":       s["status"],
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
            "progress":     "Terminé",
            "progress_pct": 100,
            "url":          report["target"],
            "error":        report.get("error"),
            "summary":      report.get("summary"),
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
