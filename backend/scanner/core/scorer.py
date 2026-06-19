"""
Risk score calculator.
Maps severity × confidence to a numeric score in [0, 100].
"""
from typing import Any, Dict, List

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
    """
    Return a risk score in [0, 100].
    Score = min(100, Σ(severity_weight × confidence_multiplier)).
    Findings without a confidence field are treated as 'medium'.
    """
    total = 0.0
    for f in findings:
        sev  = (f.get("severity")   or "info").lower()
        conf = (f.get("confidence") or "medium").lower()
        base = _SEVERITY_SCORES.get(sev, 1.0)
        mult = _CONFIDENCE_MULT.get(conf, 0.5)
        total += base * mult
    return min(100, round(total))
