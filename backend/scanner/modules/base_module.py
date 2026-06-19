"""Abstract base for all passive audit detection modules."""
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.core.http_client import AuditHttpClient
from backend.utils.logger import setup_logger
from config import LOGS_DIR


class BaseModule(ABC):
    NAME:     str = "base"
    CATEGORY: str = "General"

    def __init__(self, client: AuditHttpClient) -> None:
        self._client = client
        self._log    = setup_logger(f"module.{self.NAME}", LOGS_DIR / "scanner.log")

    @abstractmethod
    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Run module against *url*. Return list of findings (may be empty)."""

    def _finding(
        self,
        *,
        name: str,
        severity: str,
        confidence: str,
        description: str,
        url: str,
        evidence: str = "",
        impact: str = "",
        recommendation: str = "",
        location: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "name":           name,
            "category":       self.CATEGORY,
            "severity":       severity,
            "confidence":     confidence,
            "location":       location or url,
            "description":    description,
            "evidence":       evidence[:800] if evidence else "",
            "impact":         impact,
            "recommendation": recommendation,
        }

    @staticmethod
    def _base_url(url: str) -> str:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _dedup(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        out = []
        for f in findings:
            key = (f.get("name", ""), f.get("location", "")[:80])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
