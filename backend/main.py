"""
SQL Audit Scanner - API (mode agent pentest automatisé)

Flow : targets.txt → pipeline → CSV
"""
import asyncio
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import FRONTEND_DIR, LOGS_DIR, REPORTS_CSV_DIR, TARGETS_FILE
from backend.reporter.report_generator import ReportGenerator
from backend.scanner.csv_exporter import list_csv_files
from backend.scanner.scan_pipeline import run_full_pipeline
from backend.scanner.sqlmap_runner import SQLMapRunner
from backend.utils.logger import setup_logger
from backend.utils.validators import validate_url

logger = setup_logger("main", LOGS_DIR / "app.log")

app = FastAPI(
    title="Pentest Audit Scanner",
    description="Agent de pentest automatisé — local use only",
    version="5.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_runner   = SQLMapRunner()
_reporter = ReportGenerator()
_scans: Dict[str, Dict[str, Any]] = {}
_event_log: deque = deque(maxlen=200)
_last_batch_ids: List[str] = []
_batch_started_at: Optional[datetime] = None


def _log_event(scan_id: str, url: str, msg: str, pct: int = 0) -> None:
    _event_log.appendleft({
        "ts":      datetime.now().strftime("%H:%M:%S"),
        "scan_id": scan_id,
        "url":     url,
        "msg":     msg,
        "pct":     pct,
    })


# ── Request schemas ────────────────────────────────────────────
class ScanRequest(BaseModel):
    urls: List[str]
    config: Optional[Dict[str, Any]] = None


# ── helpers ────────────────────────────────────────────────────

def _parse_targets(raw: str) -> List[str]:
    """Parse un fichier targets.txt : une URL par ligne, # = commentaire."""
    urls = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ok, _ = validate_url(line)
        if ok:
            urls.append(line)
    return urls


# ── Background scan task ───────────────────────────────────────

async def _run_scan(scan_id: str, url: str, config: Dict[str, Any]) -> None:
    start = datetime.now()

    def _upd(**kw: Any) -> None:
        _scans[scan_id].update(kw)

    def _progress(msg: str, done: int, total: int) -> None:
        pct = min(92, done)
        _upd(progress=msg, progress_pct=pct)
        _log_event(scan_id, url, msg, pct)

    try:
        _upd(status="running", progress="Démarrage pipeline…", progress_pct=3)
        logger.info(f"[{scan_id}] Scan → {url}")

        pipeline = await run_full_pipeline(
            url=url,
            scan_id=scan_id,
            config=config,
            progress_callback=_progress,
            sqlmap_runner=_runner,
        )

        end = datetime.now()
        _upd(progress="Génération rapport…", progress_pct=90)

        report = _reporter.generate(
            scan_id=scan_id,
            url=url,
            pipeline_result=pipeline,
            status="completed",
            start_time=start,
            end_time=end,
            scan_config=config,
        )

        _upd(
            status="completed",
            report=report,
            progress="Terminé",
            progress_pct=100,
            csv_files=[{"filename": Path(p).name,
                        "size_kb": round(Path(p).stat().st_size / 1024, 1),
                        "type": "summary" if "summary" in Path(p).name
                                else "findings" if "findings" in Path(p).name else "data"}
                       for p in pipeline.get("csv_files", []) if Path(p).exists()],
            sqli_confirmed=pipeline.get("sqli_confirmed", False),
        )
        logger.info(
            f"[{scan_id}] Done — {len(pipeline['findings'])} findings "
            f"score={pipeline['risk_score']} sqli={pipeline['sqli_confirmed']}"
        )

    except Exception as exc:
        end = datetime.now()
        logger.error(f"[{scan_id}] Fatal: {exc}", exc_info=True)
        _upd(status="failed", error=str(exc), progress_pct=0)
        _reporter.generate_error(
            scan_id=scan_id, url=url, error=str(exc),
            start_time=start, end_time=end, scan_config=config,
        )
    finally:
        _runner.cleanup(scan_id)


# ── API routes ─────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Stats temps réel pour la page Stats du frontend — dernier batch uniquement."""
    # Filtrer sur le dernier batch lancé
    batch = {sid: _scans[sid] for sid in _last_batch_ids if sid in _scans}

    active    = [s for s in batch.values() if s.get("status") == "running"]
    completed = [s for s in batch.values() if s.get("status") == "completed"]
    failed    = [s for s in batch.values() if s.get("status") == "failed"]

    total_vulns = 0
    sqli_count  = 0
    dbs_count   = 0
    for s in completed:
        rep = s.get("report") or {}
        total_vulns += len(rep.get("findings", []) or [])
        if s.get("sqli_confirmed"):
            sqli_count += 1
            dbs_count  += len(s.get("csv_files", []))

    all_done = len(active) == 0 and len(_last_batch_ids) > 0
    batch_duration_s = None
    if _batch_started_at:
        batch_duration_s = round((datetime.now() - _batch_started_at).total_seconds())

    return {
        "active_count":      len(active),
        "completed_count":   len(completed),
        "failed_count":      len(failed),
        "total_vulns":       total_vulns,
        "sqli_confirmed":    sqli_count,
        "dbs_extracted":     dbs_count,
        "batch_started_at":  _batch_started_at.isoformat() if _batch_started_at else None,
        "batch_duration_s":  batch_duration_s,
        "batch_done":        all_done,
        "active_scans": [
            {
                "scan_id":      s["scan_id"],
                "url":          s["url"],
                "progress":     s.get("progress", ""),
                "progress_pct": s.get("progress_pct", 0),
            }
            for s in active
        ],
        "events": list(_event_log)[:60],
    }


@app.get("/api/health")
async def health():
    import shutil as _sh
    return {
        "status":           "ok",
        "sqlmap_available": _sh.which("sqlmap") is not None,
        "active_scans":     sum(1 for s in _scans.values() if s["status"] == "running"),
        "version":          "5.0.0",
    }


@app.post("/api/scan/start", status_code=202)
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    """Lance un scan pour chaque URL fournie."""
    valid_urls = []
    for url in req.urls:
        ok, reason = validate_url(url)
        if ok:
            valid_urls.append(url)
        else:
            logger.warning(f"URL ignorée — {url}: {reason}")

    if not valid_urls:
        raise HTTPException(status_code=422, detail="Aucune URL valide")

    global _last_batch_ids, _batch_started_at
    cfg = req.config or {}
    _batch_started_at = datetime.now()
    ids = []
    for url in valid_urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id":      sid,
            "url":          url,
            "status":       "pending",
            "progress":     "En attente",
            "progress_pct": 0,
            "started_at":   datetime.now().isoformat(),
            "report":       None,
            "csv_files":    [],
            "sqli_confirmed": False,
            "error":        None,
        }
        bg.add_task(_run_scan, sid, url, cfg)
        ids.append(sid)

    _last_batch_ids = ids
    logger.info(f"Lancé {len(ids)} scan(s)")
    return {"scan_ids": ids, "queued": len(ids)}


@app.post("/api/targets/upload", status_code=202)
async def upload_targets(file: UploadFile, bg: BackgroundTasks):
    """Upload targets.txt et lance un scan par URL valide."""
    raw = (await file.read()).decode("utf-8", errors="replace")
    urls = _parse_targets(raw)

    if not urls:
        raise HTTPException(status_code=422, detail="Aucune URL valide dans le fichier")

    # Sauvegarder pour référence
    TARGETS_FILE.write_text(raw, encoding="utf-8")

    global _last_batch_ids, _batch_started_at
    _batch_started_at = datetime.now()
    ids = []
    for url in urls:
        sid = uuid.uuid4().hex[:10]
        _scans[sid] = {
            "scan_id":      sid,
            "url":          url,
            "status":       "pending",
            "progress":     "En attente",
            "progress_pct": 0,
            "started_at":   datetime.now().isoformat(),
            "report":       None,
            "csv_files":    [],
            "sqli_confirmed": False,
            "error":        None,
        }
        bg.add_task(_run_scan, sid, url, {})
        ids.append(sid)

    _last_batch_ids = ids
    logger.info(f"targets.txt → {len(ids)} cibles")
    return {"scan_ids": ids, "queued": len(ids), "urls": urls}


@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    if scan_id in _scans:
        s   = _scans[scan_id]
        rep = s.get("report") or {}
        return {
            "scan_id":        scan_id,
            "status":         s["status"],
            "progress":       s.get("progress"),
            "progress_pct":   s.get("progress_pct", 0),
            "url":            s["url"],
            "error":          s.get("error"),
            "sqli_confirmed": s.get("sqli_confirmed", False),
            "csv_files":      s.get("csv_files", []),
            "summary":        rep.get("summary") if rep else None,
        }

    report = _reporter.load(scan_id)
    if report:
        return {
            "scan_id":        scan_id,
            "status":         report["status"],
            "progress":       "Terminé",
            "progress_pct":   100,
            "url":            report["target"],
            "error":          report.get("error"),
            "sqli_confirmed": report.get("scan_summary", {}).get("sqli_confirmed", False),
            "csv_files":      list_csv_files(scan_id),
            "summary":        report.get("summary"),
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


@app.get("/api/scan/{scan_id}/csv")
async def list_scan_csvs(scan_id: str):
    """Liste les CSV disponibles pour un scan."""
    return {"scan_id": scan_id, "files": list_csv_files(scan_id)}


@app.get("/api/scan/{scan_id}/csv/{filename}")
async def download_csv(scan_id: str, filename: str):
    """Télécharge un fichier CSV produit par le scan."""
    # Validation stricte du nom de fichier
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Nom de fichier invalide")
    path = REPORTS_CSV_DIR / scan_id / filename
    if not path.exists() or not path.suffix == ".csv":
        raise HTTPException(status_code=404, detail="Fichier CSV introuvable")
    return FileResponse(
        str(path),
        media_type="text/csv",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/tables")
async def list_tables(scan_id: str):
    """Liste les bases et tables extraites par SQLMap (CSV format db__table.csv)."""
    import csv as _csv
    dir_path = REPORTS_CSV_DIR / scan_id
    if not dir_path.exists():
        return {"scan_id": scan_id, "databases": []}

    dbs: Dict[str, List[Dict]] = {}
    for f in sorted(dir_path.glob("*.csv")):
        name = f.stem
        if "__" not in name:
            continue
        db_name, table_name = name.split("__", 1)
        row_count = 0
        with open(f, newline="", encoding="utf-8", errors="replace") as fh:
            for _ in fh:
                row_count += 1
        dbs.setdefault(db_name, []).append({
            "table":    table_name,
            "filename": f.name,
            "row_count": max(0, row_count - 1),
        })

    return {
        "scan_id":   scan_id,
        "databases": [{"name": db, "tables": tables} for db, tables in sorted(dbs.items())],
    }


@app.get("/api/scan/{scan_id}/table/{filename}")
async def read_table(
    scan_id:  str,
    filename: str,
    page:     int = 1,
    per_page: int = 50,
    search:   str = "",
    sort_col: str = "",
    sort_dir: str = "asc",
):
    """Lecture paginée d'un CSV extrait — max 500 lignes en mémoire, déduplication incluse."""
    import csv as _csv
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Nom de fichier invalide")
    if not filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="CSV uniquement")
    path = REPORTS_CSV_DIR / scan_id / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier introuvable")

    per_page = max(1, min(per_page, 100))
    MAX_ROWS = 500

    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader  = _csv.DictReader(fh)
        columns = list(reader.fieldnames or [])
        seen:   set = set()
        rows:   List[Dict] = []
        for row in reader:
            if len(rows) >= MAX_ROWS:
                break
            d       = dict(row)
            row_key = tuple(d.values())
            if row_key in seen:
                continue
            seen.add(row_key)
            if search:
                s = search.lower()
                if not any(s in str(v).lower() for v in d.values()):
                    continue
            rows.append(d)

    if sort_col and sort_col in columns:
        rows.sort(
            key=lambda r: (r.get(sort_col) or "").lower(),
            reverse=(sort_dir == "desc"),
        )

    total      = len(rows)
    page       = max(1, page)
    start      = (page - 1) * per_page
    total_pages = max(1, (total + per_page - 1) // per_page)

    return {
        "filename":    filename,
        "columns":     columns,
        "rows":        rows[start: start + per_page],
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": total_pages,
        "capped_at":   MAX_ROWS,
        "search":      search,
        "sort_col":    sort_col,
        "sort_dir":    sort_dir,
    }


@app.get("/api/reports")
async def list_reports():
    return _reporter.list_all()


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    removed_mem = scan_id in _scans
    if removed_mem:
        del _scans[scan_id]
    removed_file = _reporter.delete(scan_id)
    if not removed_mem and not removed_file:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"deleted": scan_id}


# ── Frontend ───────────────────────────────────────────────────
_static = FRONTEND_DIR / "static"
if _static.exists():
    app.mount("/static", StaticFiles(directory=str(_static)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    idx = FRONTEND_DIR / "index.html"
    if idx.exists():
        return FileResponse(str(idx))
    return JSONResponse({"error": "Frontend introuvable"}, status_code=404)


@app.get("/{full_path:path}", include_in_schema=False)
async def catch_all(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404)
    idx = FRONTEND_DIR / "index.html"
    if idx.exists():
        return FileResponse(str(idx))
    raise HTTPException(status_code=404)
