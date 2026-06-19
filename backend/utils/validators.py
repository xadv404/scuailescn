"""
SQL Audit Scanner - Input validation helpers
"""
import re
from urllib.parse import urlparse
from typing import List, Tuple


def validate_url(url: str) -> Tuple[bool, str]:
    """Return (True, '') on success or (False, reason) on failure."""
    url = url.strip()
    if not url:
        return False, "Empty URL"

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, "Protocol must be http or https"

    if not parsed.netloc:
        return False, "Missing domain / host"

    # Block obviously malformed host strings
    if re.search(r"[<>\"'\\]", parsed.netloc):
        return False, "Invalid characters in host"

    return True, ""


def validate_urls(urls: List[str]) -> Tuple[bool, List[str]]:
    """Validate a list of URLs.  Returns (all_valid, [error_messages])."""
    errors: List[str] = []
    for url in urls:
        ok, reason = validate_url(url)
        if not ok:
            errors.append(f"{url!r}: {reason}")
    return (len(errors) == 0), errors
