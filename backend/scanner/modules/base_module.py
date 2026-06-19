"""Abstract base for all passive audit detection modules."""
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.scanner.core.http_client import AuditHttpClient
from backend.utils.logger import setup_logger
from config import LOGS_DIR


class BaseModule(ABC):
    """Every passive module inherits this class."""

    NAME:     str = "base"
    CATEGORY: str = "Général"

    def __init__(self, client: AuditHttpClient) -> None:
        self._client = client
        self._log    = setup_logger(f"module.{self.NAME}", LOGS_DIR / "scanner.log")

    @abstractmethod
    async def scan(self, url: str) -> List[Dict[str, Any]]:
        """Run the module against *url* and return a (possibly empty) findings list."""

    def _finding(
        self,
        *,
        type: str,
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
            "type":           type,
            "category":       self.CATEGORY,
            "severity":       severity,
            "confidence":     confidence,
            "location":       location or url,
            "description":    description,
            "evidence":       evidence[:600] if evidence else "",
            "impact":         impact,
            "recommendation": recommendation,
        }
