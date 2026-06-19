"""
SQL Audit Scanner - Report generator

Produces professional JSON reports suitable for client delivery.
  • scan_config  – parameters used (secrets masked)
  • scan_summary – statistics, DB engine, risk level
  • findings     – sorted critical→info, with impact + recommendation
  • recommendations – deduplicated action list for the client
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

logger = setup_logger("reporter", LOGS_DIR / "scanner.log")

_TOOL_VERSION  = "2.0.0"
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportGenerator:
    """Build and persist JSON audit reports."""

    # ── Public API ─────────────────────────────────────────────────

    def generate(
        self,
        *,
        scan_id: str,
        url: str,
        findings: List[Dict[str, Any]],
        status: str,
        start_time: datetime,
        end_time: datetime,
        error: Optional[str] = None,
        scan_config: Optional[Dict[str, Any]] = None,
        scan_summary: Optional[Dict[str, Any]] = None,
        database_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create, save, and return a complete audit report dict."""
        duration = round((end_time - start_time).total_seconds(), 2)

        # Sort findings: critical first, info last
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(f.get("severity", "info"))
            if f.get("severity", "info") in _SEVERITY_ORDER
            else 99,
        )

        # Severity counts for the lightweight 'summary' (used by status endpoint)
        sev_count = {s: 0 for s in _SEVERITY_ORDER}
        for f in sorted_findings:
            sev = f.get("severity", "info")
            if sev in sev_count:
                sev_count[sev] += 1

        risk_level = self._overall_risk(sev_count)
        vulnerable = sev_count["critical"] > 0 or sev_count["high"] > 0

        # If caller didn't supply a scan_summary, build a minimal one
        if scan_summary is None:
            scan_summary = {
                "total_findings":   len(sorted_findings),
                "risk_level":       risk_level,
                "database_type":    database_type or "Non détecté",
                "database_engines": {database_type: 1} if database_type else {},
                "severity":         sev_count,
                "vulnerable":       vulnerable,
            }

        # Deduplicated action list for the client remediation section
        recommendations = self._build_recommendations(sorted_findings)

        # Mask secrets in the config before embedding in the report
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
            "date":             start_time.isoformat(),
            "end_date":         end_time.isoformat(),
            "duration_seconds": duration,
            "status":           status,
            "scan_config":      safe_config,
            "scan_summary":     scan_summary,
            # Kept for backward compat with status endpoint polling
            "summary": {
                "total_findings":    len(sorted_findings),
                "risk_level":        risk_level,
                "severity_breakdown": sev_count,
                "vulnerable":        vulnerable,
                "database_type":     database_type or "Non détecté",
            },
            "findings":         sorted_findings,
            "recommendations":  recommendations,
            "error":            error,
        }

        self._save(scan_id, report)
        return report

    def load(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Load a previously saved report, or None if not found."""
        path = REPORTS_DIR / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error(f"Cannot load report {scan_id}: {exc}")
            return None

    def list_all(self) -> List[Dict[str, Any]]:
        """Return a summary list of all saved reports, newest first."""
        summaries = []
        for f in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                ss = data.get("scan_summary") or data.get("summary", {})
                summaries.append(
                    {
                        "scan_id":       data.get("scan_id"),
                        "target":        data.get("target"),
                        "date":          data.get("date"),
                        "status":        data.get("status"),
                        "risk_level":    ss.get("risk_level", "N/A"),
                        "total_findings":ss.get("total_findings", 0),
                        "vulnerable":    ss.get("vulnerable", False),
                        "database_type": ss.get("database_type", "—"),
                    }
                )
            except Exception as exc:
                logger.warning(f"Skipping malformed report {f.name}: {exc}")
        return summaries

    def delete(self, scan_id: str) -> bool:
        """Delete a report file. Returns True if deleted."""
        path = REPORTS_DIR / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            logger.info(f"Report {scan_id} deleted")
            return True
        return False

    # ── Private helpers ────────────────────────────────────────────

    def _save(self, scan_id: str, report: Dict[str, Any]) -> None:
        path = REPORTS_DIR / f"{scan_id}.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Report saved → {path}")

    @staticmethod
    def _overall_risk(counts: Dict[str, int]) -> str:
        for level in _SEVERITY_ORDER:
            if counts.get(level, 0) > 0:
                return level.upper()
        return "NONE"

    @staticmethod
    def _build_recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build a deduplicated, prioritised recommendation list.
        Each entry has a title (description) and the full recommendation text,
        making it easy to copy-paste into a client remediation plan.
        """
        seen: set = set()
        result: List[Dict[str, Any]] = []

        for f in findings:
            rec = f.get("recommendation", "").strip()
            if rec and rec not in seen:
                seen.add(rec)
                result.append(
                    {
                        "priority":       f.get("severity", "info").upper(),
                        "related_finding": f.get("description", f.get("type", "—")),
                        "action":         rec,
                    }
                )
        return result
