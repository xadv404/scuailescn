"""
Report generator for the v4/v5 pipeline.

Produces a clean JSON audit report from pipeline results.
Secrets in scan_config are always masked before persistence.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR, REPORTS_DIR
from backend.utils.logger import setup_logger
from backend.utils.validators import sanitize_config_for_report

logger = setup_logger("reporter_v2", LOGS_DIR / "scanner.log")

_TOOL_VERSION   = "5.0.0"
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportGenerator:
    """Build and persist JSON audit reports (pipeline v5)."""

    def generate(
        self,
        *,
        scan_id: str,
        url: str,
        pipeline_result: Dict[str, Any],
        status: str,
        start_time: datetime,
        end_time: datetime,
        scan_config: Optional[Dict[str, Any]] = None,
        scan_type: str = "full_scan",
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build, persist and return a full audit report.

        pipeline_result is the dict returned by run_audit_pipeline().
        """
        duration = round((end_time - start_time).total_seconds(), 2)
        findings  = pipeline_result.get("findings", [])
        summary   = pipeline_result.get("summary", {})
        phases    = pipeline_result.get("phases", [])
        recs      = pipeline_result.get("recommendations", [])
        risk_score = pipeline_result.get("risk_score", 0)
        risk_level = pipeline_result.get("risk_level", "NONE")
        technologies = pipeline_result.get("technologies", [])
        database_type = pipeline_result.get("database_type")

        # Severity counts
        sev_count = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in sev_count:
                sev_count[sev] += 1

        safe_config = sanitize_config_for_report(scan_config) if scan_config else {}

        report: Dict[str, Any] = {
            "report_metadata": {
                "tool":         "SQL Audit Scanner",
                "version":      _TOOL_VERSION,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "disclaimer": (
                    "Ce rapport a été généré par un outil d'audit de sécurité autorisé. "
                    "Son contenu est confidentiel et destiné exclusivement au personnel "
                    "autorisé. Ne pas distribuer sans autorisation explicite."
                ),
            },
            "scan_id":          scan_id,
            "target":           url,
            "scan_type":        scan_type,
            "date":             start_time.isoformat(),
            "end_date":         end_time.isoformat(),
            "duration_seconds": duration,
            "status":           status,
            "error":            error,
            "scan_config":      safe_config,
            "scan_summary": {
                "total_findings": len(findings),
                "risk_score":     risk_score,
                "risk_level":     risk_level,
                "database_type":  database_type or "Non détecté",
                "technologies":   technologies,
                "severity":       sev_count,
                "vulnerable":     risk_score > 0,
                "categories":     summary.get("categories", {}),
                "phases":         phases,
                "duration_s":     pipeline_result.get("duration_s", duration),
            },
            # Lightweight summary kept for status endpoint compatibility
            "summary": {
                "total_findings":     len(findings),
                "risk_level":         risk_level,
                "risk_score":         risk_score,
                "severity_breakdown": sev_count,
                "vulnerable":         risk_score > 0,
                "database_type":      database_type or "Non détecté",
            },
            "findings":        findings,
            "recommendations": recs,
        }

        self._save(scan_id, report)
        return report

    def generate_error(
        self,
        *,
        scan_id: str,
        url: str,
        error: str,
        start_time: datetime,
        end_time: datetime,
        scan_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.generate(
            scan_id=scan_id,
            url=url,
            pipeline_result={"findings": [], "risk_score": 0, "risk_level": "NONE",
                             "summary": {}, "recommendations": [], "phases": [],
                             "technologies": [], "database_type": None, "duration_s": 0},
            status="failed",
            start_time=start_time,
            end_time=end_time,
            scan_config=scan_config,
            error=error,
        )

    def load(self, scan_id: str) -> Optional[Dict[str, Any]]:
        path = REPORTS_DIR / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error(f"Cannot load report {scan_id}: {exc}")
            return None

    def list_all(self) -> List[Dict[str, Any]]:
        summaries = []
        for f in sorted(
            REPORTS_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                ss   = data.get("scan_summary") or data.get("summary", {})
                summaries.append({
                    "scan_id":        data.get("scan_id"),
                    "target":         data.get("target"),
                    "date":           data.get("date"),
                    "status":         data.get("status"),
                    "scan_type":      data.get("scan_type", "audit"),
                    "risk_level":     ss.get("risk_level", "N/A"),
                    "risk_score":     ss.get("risk_score", 0),
                    "total_findings": ss.get("total_findings", 0),
                    "vulnerable":     ss.get("vulnerable", False),
                    "database_type":  ss.get("database_type", "—"),
                })
            except Exception as exc:
                logger.warning(f"Skipping malformed report {f.name}: {exc}")
        return summaries

    def delete(self, scan_id: str) -> bool:
        path = REPORTS_DIR / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            logger.info(f"Report {scan_id} deleted")
            return True
        return False

    def _save(self, scan_id: str, report: Dict[str, Any]) -> None:
        path = REPORTS_DIR / f"{scan_id}.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Report saved → {path}")
