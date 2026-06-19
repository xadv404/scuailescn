"""
SQL Audit Scanner - Input validation and sanitisation helpers
"""
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# ── Secrets that must never appear in plain text in logs or reports ──
_SECRET_KEYS = re.compile(
    r"(auth_bearer|bearer|token|password|passwd|pwd|secret|cookie)",
    re.IGNORECASE,
)


# ════════════════════════════════════════════════════════════════
# URL validation
# ════════════════════════════════════════════════════════════════

def validate_url(url: str) -> Tuple[bool, str]:
    """Return (True, '') on success or (False, reason) on failure."""
    url = url.strip()
    if not url:
        return False, "URL vide"

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Erreur de parsing : {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, "Le protocole doit être http ou https"

    if not parsed.netloc:
        return False, "Domaine / hôte manquant"

    # Block shell-injection characters in the host part
    if re.search(r"[<>\"'\\;&|`$]", parsed.netloc):
        return False, "Caractères interdits dans le nom d'hôte"

    # Block path-traversal attempts
    if ".." in url:
        return False, "Séquence de traversée de chemin refusée"

    return True, ""


def validate_urls(urls: List[str]) -> Tuple[bool, List[str]]:
    """Validate a list of URLs. Returns (all_valid, [error_messages])."""
    errors: List[str] = []
    for url in urls:
        ok, reason = validate_url(url)
        if not ok:
            errors.append(f"{url!r} : {reason}")
    return (len(errors) == 0), errors


# ════════════════════════════════════════════════════════════════
# Scan config validation
# ════════════════════════════════════════════════════════════════

def validate_scan_config(cfg: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate and clamp scan configuration values.
    Returns (valid, [error_messages]).
    """
    errors: List[str] = []

    if "level" in cfg:
        try:
            lvl = int(cfg["level"])
            if not (1 <= lvl <= 5):
                errors.append("level doit être compris entre 1 et 5")
        except (TypeError, ValueError):
            errors.append("level doit être un entier")

    if "risk" in cfg:
        try:
            rsk = int(cfg["risk"])
            if not (1 <= rsk <= 2):
                errors.append("risk doit être 1 ou 2 (max 2 en mode audit)")
        except (TypeError, ValueError):
            errors.append("risk doit être un entier")

    if "threads" in cfg:
        try:
            thr = int(cfg["threads"])
            if not (1 <= thr <= 10):
                errors.append("threads doit être compris entre 1 et 10")
        except (TypeError, ValueError):
            errors.append("threads doit être un entier")

    if "timeout" in cfg:
        try:
            tmo = int(cfg["timeout"])
            if not (10 <= tmo <= 120):
                errors.append("timeout doit être compris entre 10 et 120 secondes")
        except (TypeError, ValueError):
            errors.append("timeout doit être un entier")

    if "techniques" in cfg:
        allowed = set("BEUSTQ")
        given   = set(str(cfg["techniques"]).upper())
        if not given.issubset(allowed):
            errors.append(f"techniques invalides : {given - allowed}. Autorisées : B E U S T Q")

    return (len(errors) == 0), errors


# ════════════════════════════════════════════════════════════════
# Secret masking (for logs and reports)
# ════════════════════════════════════════════════════════════════

def mask_secrets(value: str) -> str:
    """Replace sensitive substrings in a string with [MASQUÉ].

    Handles all common separators:
      key=value  key: value  Bearer <token>  Authorization Bearer token
    """
    return re.sub(
        # separator: = | : | whitespace (e.g. "Bearer <token>")
        r"(bearer|token|session|password|passwd|pwd|secret|key)(?:\s*[=:]\s*|\s+)(\S+)",
        r"\1=[MASQUÉ]",
        value,
        flags=re.IGNORECASE,
    )


def sanitize_config_for_report(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of the scan config safe to embed in a report:
    secret fields are replaced with a placeholder.
    """
    MASK = "[MASQUÉ]"
    safe: Dict[str, Any] = {}
    for key, val in cfg.items():
        if _SECRET_KEYS.search(key) and val:
            safe[key] = MASK
        elif isinstance(val, str):
            safe[key] = mask_secrets(val)
        else:
            safe[key] = val
    return safe
