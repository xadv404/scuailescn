"""
SQL Audit Scanner - Data Extraction Module  [FUTURE USE — DISABLED]

════════════════════════════════════════════════════════════════════
  WARNING — LEGAL NOTICE
════════════════════════════════════════════════════════════════════
This module is DISABLED by default (ALLOW_EXTRACTION_MODE = False).

It is reserved for future authorised data-validation engagements where
the client explicitly requests proof-of-data-access as part of the
penetration test scope.

Enabling it without written authorisation from the target system's owner
constitutes an illegal act in most jurisdictions.
════════════════════════════════════════════════════════════════════

Architecture note:
  • This module is entirely separate from the main audit scanner.
  • Output is stored exclusively in reports/extraction/ (never mixed with
    standard audit reports).
  • Each extraction run requires:
      - scan_id from a prior completed audit scan
      - explicit written authorisation reference
  • No extraction is possible if ALLOW_EXTRACTION_MODE is False.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import (
    ALLOW_EXTRACTION_MODE,
    EXTRACTION_DIR,
    LOGS_DIR,
    SQLMAP_PATH,
    SQLMAP_TIMEOUT,
    TEMP_DIR,
)
from backend.utils.logger import setup_logger

logger = setup_logger("extractor", LOGS_DIR / "extractor.log")


class ExtractionNotAuthorisedError(RuntimeError):
    """Raised when extraction mode has not been explicitly enabled."""


class DataExtractor:
    """
    Future capability: controlled data extraction for authorised
    proof-of-concept validation.

    NOT IMPLEMENTED — placeholder for v3+ roadmap.
    """

    def __init__(self, authorisation_ref: str = "") -> None:
        if not ALLOW_EXTRACTION_MODE:
            raise ExtractionNotAuthorisedError(
                "Le mode extraction est désactivé. "
                "Définissez ALLOW_EXTRACTION_MODE = True dans config.py "
                "uniquement après avoir obtenu une autorisation écrite explicite "
                "de l'administrateur du système cible."
            )
        if not authorisation_ref.strip():
            raise ValueError(
                "Une référence d'autorisation est obligatoire pour toute opération d'extraction."
            )
        self._auth_ref = authorisation_ref
        EXTRACTION_DIR.mkdir(parents=True, exist_ok=True)
        logger.warning(
            f"DataExtractor initialised — ALLOW_EXTRACTION_MODE=True "
            f"— authorisation_ref={authorisation_ref!r}"
        )

    async def extract(
        self,
        audit_scan_id: str,
        url: str,
        tables: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Placeholder: perform a controlled --dump on specified tables.

        Parameters
        ----------
        audit_scan_id : str
            The scan_id of the audit run that confirmed the vulnerability.
        url : str
            Target URL (must match the audit scan target).
        tables : list[str] | None
            Explicit list of table names to dump.  None = none (not all).
        config : dict | None
            Same scan config dict as the main runner.

        Raises
        ------
        NotImplementedError
            This method is not yet implemented.
        """
        raise NotImplementedError(
            "La fonctionnalité d'extraction n'est pas encore implémentée. "
            "Ce module est réservé aux futures extensions d'audit autorisées."
        )

    def _build_extraction_report_path(self, extraction_id: str) -> Path:
        """Return the output path for an extraction report."""
        return EXTRACTION_DIR / f"{extraction_id}.json"

    def _save_extraction_manifest(
        self,
        extraction_id: str,
        audit_scan_id: str,
        url: str,
        authorisation_ref: str,
    ) -> Path:
        """
        Write an audit-trail manifest before any extraction begins.
        The manifest records who authorised the operation and when.
        """
        manifest = {
            "extraction_id":    extraction_id,
            "audit_scan_id":    audit_scan_id,
            "target":           url,
            "authorisation_ref": authorisation_ref,
            "initiated_at":     datetime.utcnow().isoformat() + "Z",
            "status":           "initiated",
            "warning": (
                "This file records an authorised data extraction operation. "
                "It must be retained as part of the engagement audit trail."
            ),
        }
        path = EXTRACTION_DIR / f"{extraction_id}_manifest.json"
        path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Extraction manifest written → {path}")
        return path
