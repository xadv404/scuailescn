"""
Central result analysis, deduplication, and risk scoring.
"""
from typing import Any, Dict, List, Optional

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_SEVERITY_SCORES: Dict[str, float] = {
    "critical": 30.0,
    "high":     20.0,
    "medium":   10.0,
    "low":       3.0,
    "info":      1.0,
}

_CONFIDENCE_MULT: Dict[str, float] = {
    "confirmed": 1.00,
    "high":      0.85,
    "medium":    0.65,
    "low":       0.40,
    "unknown":   0.50,
}


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """Return an integer risk score in [0, 100]."""
    total = 0.0
    for f in findings:
        sev  = (f.get("severity")   or "info").lower()
        conf = (f.get("confidence") or "medium").lower()
        total += _SEVERITY_SCORES.get(sev, 1.0) * _CONFIDENCE_MULT.get(conf, 0.5)
    return min(100, round(total))


def risk_label(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 15: return "MEDIUM"
    if score > 0:   return "LOW"
    return "NONE"


def build_scan_summary(
    findings: List[Dict[str, Any]],
    database_type: Optional[str],
    technologies: List[str],
    risk_score: int,
    scan_type: str = "audit",
    database_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sev_count: Dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    categories: Dict[str, Dict] = {}

    for f in findings:
        sev = (f.get("severity") or "info").lower()
        cat = f.get("category", "General")
        if sev in sev_count:
            sev_count[sev] += 1
        if cat not in categories:
            categories[cat] = {"count": 0, "severity": {s: 0 for s in _SEVERITY_ORDER}}
        categories[cat]["count"] += 1
        if sev in categories[cat]["severity"]:
            categories[cat]["severity"][sev] += 1

    level = risk_label(risk_score)

    summary: Dict[str, Any] = {
        "total_findings":  len(findings),
        "risk_score":      risk_score,
        "risk_level":      level,
        "database_type":   database_type or "Non détecté",
        "technologies":    technologies,
        "severity":        sev_count,
        "categories":      categories,
        "vulnerable":      risk_score > 0,
        "scan_type":       scan_type,
    }
    if database_info:
        summary["database_info"] = database_info
    return summary


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out = []
    for f in findings:
        key = f.get("name") or f.get("type") or f.get("description", "")
        loc = f.get("location", "")
        uid = f"{key}|{loc[:80]}"
        if uid not in seen:
            seen.add(uid)
            out.append(f)
    return out


def sort_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def _k(f: Dict) -> int:
        s = (f.get("severity") or "info").lower()
        return _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else 99
    return sorted(findings, key=_k)


def build_recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out = []
    for f in sort_by_severity(findings):
        rec = (f.get("recommendation") or "").strip()
        if rec and rec not in seen:
            seen.add(rec)
            out.append({
                "priority":        (f.get("severity") or "info").upper(),
                "related_finding": f.get("name") or f.get("description", "—"),
                "action":          rec,
            })
    return out
