"""
CSV Exporter — génère des CSV propres à partir des findings et des dumps SQLMap.

Fichiers produits (dans reports/csv/{scan_id}/) :
  findings.csv          — toutes les vulnérabilités détectées
  summary.csv           — résumé global du scan
  {db}__{table}.csv     — données extraites par SQLMap (si injection)
"""
import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR, REPORTS_CSV_DIR
from backend.utils.logger import setup_logger

logger = setup_logger("csv_exporter", LOGS_DIR / "scanner.log")

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def export_findings_csv(
    findings: List[Dict[str, Any]],
    scan_id: str,
    url: str,
) -> Optional[str]:
    """Génère findings.csv — une ligne par vulnérabilité."""
    if not findings:
        return None

    dest_dir = REPORTS_CSV_DIR / scan_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "findings.csv"

    fieldnames = [
        "scan_id", "target", "category", "severity", "confidence",
        "name", "description", "location", "evidence", "impact", "recommendation",
    ]

    try:
        with open(dest, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for f in sorted(
                findings,
                key=lambda x: _SEVERITY_ORDER.index(x.get("severity", "info"))
                if x.get("severity", "info") in _SEVERITY_ORDER else 99,
            ):
                row = {k: f.get(k, "") for k in fieldnames}
                row["scan_id"] = scan_id
                row["target"]  = url
                # Nettoyage des champs longs (pas de sauts de ligne dans les cellules)
                for field in ("evidence", "description", "impact", "recommendation"):
                    row[field] = str(row[field]).replace("\n", " | ").replace("\r", "")[:500]
                writer.writerow(row)

        logger.info(f"[{scan_id}] findings.csv → {dest} ({len(findings)} lignes)")
        return str(dest)

    except Exception as exc:
        logger.error(f"[{scan_id}] findings.csv failed: {exc}")
        return None


def export_summary_csv(
    scan_id: str,
    url: str,
    risk_score: int,
    risk_level: str,
    findings: List[Dict[str, Any]],
    sqli_confirmed: bool,
    database_type: Optional[str],
    technologies: List[str],
    duration_s: float,
    csv_data_files: List[str],
) -> Optional[str]:
    """Génère summary.csv — une ligne de synthèse par scan."""
    dest_dir = REPORTS_CSV_DIR / scan_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "summary.csv"

    sev_count = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in sev_count:
            sev_count[sev] += 1

    cats = list({f.get("category", "—") for f in findings})

    try:
        with open(dest, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "scan_id", "date", "target", "risk_score", "risk_level",
                "total_findings", "critical", "high", "medium", "low", "info",
                "sqli_confirmed", "database_type", "technologies",
                "categories_affected", "duration_s", "data_csvs_count",
            ])
            writer.writerow([
                scan_id,
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                url,
                risk_score,
                risk_level,
                len(findings),
                sev_count["critical"],
                sev_count["high"],
                sev_count["medium"],
                sev_count["low"],
                sev_count["info"],
                "OUI" if sqli_confirmed else "NON",
                database_type or "Non détecté",
                " | ".join(technologies),
                " | ".join(cats),
                round(duration_s, 1),
                len(csv_data_files),
            ])

        logger.info(f"[{scan_id}] summary.csv → {dest}")
        return str(dest)

    except Exception as exc:
        logger.error(f"[{scan_id}] summary.csv failed: {exc}")
        return None


def list_csv_files(scan_id: str) -> List[Dict[str, Any]]:
    """Retourne tous les CSV disponibles pour un scan_id."""
    dest_dir = REPORTS_CSV_DIR / scan_id
    if not dest_dir.exists():
        return []

    result = []
    for p in sorted(dest_dir.glob("*.csv")):
        size = p.stat().st_size
        result.append({
            "filename": p.name,
            "path":     str(p),
            "size_kb":  round(size / 1024, 1),
            "type":     "summary" if p.name == "summary.csv"
                        else "findings" if p.name == "findings.csv"
                        else "data",
        })
    return result
