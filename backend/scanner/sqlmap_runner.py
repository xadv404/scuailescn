"""
SQL Audit Scanner - SQLMap subprocess wrapper

Après le pré-filtre custom, SQLMap est lancé en mode dump complet :
  - détection interne (SQLMap gère ça lui-même)
  - dump de toutes les tables utilisateur
  - export CSV
"""
import asyncio
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import (
    ALLOW_EXTRACTION_MODE, LOGS_DIR, REPORTS_CSV_DIR,
    SCAN_DEFAULT_CONFIG, SQLMAP_PATH, SQLMAP_TIMEOUT, TEMP_DIR,
)
from backend.utils.logger import setup_logger
from backend.utils.validators import mask_secrets

logger = setup_logger("sqlmap_runner", LOGS_DIR / "scanner.log")

_SQLI_CONFIRMED_RE = re.compile(
    r"(sqlmap identified the following injection|"
    r"Parameter .+ is vulnerable|"
    r"Type:\s+(?:boolean-based|error-based|UNION query|stacked queries|time-based))",
    re.IGNORECASE,
)


class SQLMapRunner:
    """Lance SQLMap en mode dump complet — la détection est gérée en interne."""

    def _build_cmd(self, url: str, output_dir: Path, config: Dict[str, Any],
                   db_hint: Optional[str] = None) -> list:
        cfg     = {**SCAN_DEFAULT_CONFIG, **{k: v for k, v in config.items() if v is not None}}
        level   = max(1, min(int(cfg.get("level",   3)), 5))
        risk    = max(1, min(int(cfg.get("risk",    2)), 2))
        threads = max(1, min(int(cfg.get("threads", 5)), 10))
        timeout = max(10, min(int(cfg.get("timeout", 30)), 120))
        techs   = str(cfg.get("techniques", "BEUSTQ")).upper() or "BEUSTQ"

        cmd = [
            SQLMAP_PATH,
            "-u", url,
            "--batch",
            "--output-dir", str(output_dir),
            "--level",     str(level),
            "--risk",      str(risk),
            "--timeout",   str(timeout),
            "--retries",   "2",
            "--threads",   str(threads),
            "--technique", techs,
            "--flush-session",
            "-v", "0",
            "--no-cast",
            "--time-sec", "5",
        ]

        if cfg.get("test_forms", True):
            cmd.append("--forms")

        # Hint du pré-filtre pour accélérer la détection
        if db_hint:
            cmd += ["--dbms", db_hint]

        if ALLOW_EXTRACTION_MODE:
            cmd += ["--dump-all", "--exclude-sysdbs", "--csv-del", ","]
        else:
            # Mode détection uniquement (pas de dump)
            cmd += ["--banner", "--current-db", "--current-user", "--dbs", "--tables"]

        ua = str(cfg.get("user_agent", "")).strip()
        if ua:
            cmd += ["--user-agent", ua]
        cookies = str(cfg.get("cookies", "")).strip()
        if cookies:
            cmd += ["--cookie", cookies]
        bearer = str(cfg.get("auth_bearer", "")).strip()
        if bearer:
            cmd += ["--headers", f"Authorization: Bearer {bearer}"]
        headers = cfg.get("headers", {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                if str(k).strip() and str(v).strip():
                    cmd += ["--headers", f"{k}: {v}"]

        return cmd

    async def run_scan(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
        db_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Lance SQLMap en une seule passe (detect + dump).
        db_hint : hint SGBD du pré-filtre pour accélérer (ex: "mysql").
        """
        cfg = config or {}
        output_dir = TEMP_DIR / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd   = self._build_cmd(url, output_dir, cfg, db_hint=db_hint)
        start = datetime.now()
        logger.info(f"[{scan_id}] SQLMap → {mask_secrets(' '.join(str(c) for c in cmd))}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=SQLMAP_TIMEOUT,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                dur = (datetime.now() - start).total_seconds()
                logger.warning(f"[{scan_id}] SQLMap timeout {SQLMAP_TIMEOUT}s")
                return self._result(False, "", "", scan_id, output_dir, dur,
                                    error=f"Timeout {SQLMAP_TIMEOUT}s")

            stdout = stdout_b.decode("utf-8", errors="replace")
            dur    = (datetime.now() - start).total_seconds()
            sqli   = bool(_SQLI_CONFIRMED_RE.search(stdout))
            logger.info(f"[{scan_id}] SQLMap done {dur:.1f}s sqli={sqli}")
            return self._result(True, stdout,
                                stderr_b.decode("utf-8", errors="replace"),
                                scan_id, output_dir, dur, sqli_confirmed=sqli)

        except FileNotFoundError:
            logger.error(f"[{scan_id}] SQLMap introuvable : {SQLMAP_PATH}")
            return self._result(False, "", "", scan_id, output_dir, 0.0,
                                error=f"SQLMap introuvable '{SQLMAP_PATH}'")
        except Exception as exc:
            dur = (datetime.now() - start).total_seconds()
            logger.error(f"[{scan_id}] SQLMap error: {exc}")
            return self._result(False, "", "", scan_id, output_dir, dur, error=str(exc))

    def _result(
        self,
        success: bool,
        stdout: str,
        stderr: str,
        scan_id: str,
        output_dir: Path,
        duration: float,
        sqli_confirmed: bool = False,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        csv_files = self._collect_csvs(output_dir, scan_id) if success else []
        return {
            "success":        success,
            "sqli_confirmed": sqli_confirmed,
            "stdout":         stdout,
            "stderr":         stderr,
            "output_dir":     str(output_dir),
            "csv_files":      csv_files,
            "duration":       duration,
            "error":          error,
        }

    def _collect_csvs(self, output_dir: Path, scan_id: str) -> List[str]:
        dest_dir = REPORTS_CSV_DIR / scan_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        paths: List[str] = []
        for csv_path in output_dir.rglob("*.csv"):
            rel   = csv_path.relative_to(output_dir)
            parts = list(rel.parts)
            flat  = "__".join(p for p in parts if p != "dump") if len(parts) > 1 else csv_path.name
            dest  = dest_dir / flat
            try:
                shutil.copy2(str(csv_path), str(dest))
                paths.append(str(dest))
                logger.info(f"[{scan_id}] CSV → {dest.name}")
            except Exception as exc:
                logger.warning(f"[{scan_id}] CSV copy failed: {exc}")
        return paths

    def cleanup(self, scan_id: str) -> None:
        target = TEMP_DIR / scan_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            logger.info(f"[{scan_id}] Temp nettoyé")
