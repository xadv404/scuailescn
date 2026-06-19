"""
SQL Audit Scanner - SQLMap subprocess wrapper

Mode agent de pentest :
  Phase 1 : détection  (--banner --current-db --current-user --dbs --tables)
  Phase 2 : extraction (--dump-all --exclude-sysdbs) si injection confirmée
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

# Indicateurs de vulnérabilité SQLi dans la sortie SQLMap
_SQLI_CONFIRMED_RE = re.compile(
    r"(sqlmap identified the following injection|"
    r"Parameter .+ is vulnerable|"
    r"Type:\s+(?:boolean-based|error-based|UNION query|stacked queries|time-based))",
    re.IGNORECASE,
)


class SQLMapRunner:
    """Async wrapper around the sqlmap CLI — pipeline pentest en 2 phases."""

    # ── Command builders ───────────────────────────────────────────

    def _base_args(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        """Arguments communs aux deux phases."""
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
            "--level",   str(level),
            "--risk",    str(risk),
            "--timeout", str(timeout),
            "--retries", "2",
            "--threads", str(threads),
            "--technique", techs,
            "--flush-session",
            "-v", "0",           # minimal verbosity — we parse output
            "--no-cast",
            "--time-sec", "5",
        ]

        if cfg.get("test_forms", True):
            cmd.append("--forms")

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
        elif isinstance(headers, str):
            for line in headers.strip().splitlines():
                if ":" in line:
                    cmd += ["--headers", line.strip()]

        return cmd

    def _detection_cmd(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        cmd = self._base_args(url, output_dir, config)
        cmd += [
            "--banner",
            "--current-db",
            "--current-user",
            "--dbs",
            "--tables",
        ]
        return cmd

    def _extraction_cmd(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        cmd = self._base_args(url, output_dir, config)
        cmd += [
            "--dump-all",
            "--exclude-sysdbs",
            "--csv-del", ",",
        ]
        return cmd

    # ── Execution helpers ──────────────────────────────────────────

    async def _exec(self, cmd: list, scan_id: str, label: str) -> Dict[str, Any]:
        cmd_safe = " ".join(str(c) for c in cmd)
        logger.info(f"[{scan_id}] [{label}] {mask_secrets(cmd_safe)}")
        start = datetime.now()

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
                logger.warning(f"[{scan_id}] [{label}] Timeout après {SQLMAP_TIMEOUT}s")
                return {"success": False, "error": f"Timeout {label}", "duration": dur, "stdout": "", "stderr": ""}

            dur = (datetime.now() - start).total_seconds()
            logger.info(f"[{scan_id}] [{label}] Done in {dur:.1f}s rc={proc.returncode}")
            return {
                "success":    True,
                "returncode": proc.returncode,
                "stdout":     stdout_b.decode("utf-8", errors="replace"),
                "stderr":     stderr_b.decode("utf-8", errors="replace"),
                "duration":   dur,
            }

        except FileNotFoundError:
            logger.error(f"[{scan_id}] SQLMap introuvable : {SQLMAP_PATH}")
            return {"success": False, "error": f"SQLMap introuvable à '{SQLMAP_PATH}'", "duration": 0.0, "stdout": "", "stderr": ""}
        except Exception as exc:
            dur = (datetime.now() - start).total_seconds()
            logger.error(f"[{scan_id}] [{label}] Error: {exc}")
            return {"success": False, "error": str(exc), "duration": dur, "stdout": "", "stderr": ""}

    # ── Public API ─────────────────────────────────────────────────

    async def run_scan(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Pipeline complet :
          1. Détection (banner, db, tables)
          2. Extraction (dump-all) si injection trouvée et extraction activée
        Retourne dict avec stdout, csv_files, sqli_confirmed, output_dir.
        """
        cfg = config or {}
        output_dir = TEMP_DIR / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # ── Phase 1 : détection ────────────────────────────────────
        det_cmd = self._detection_cmd(url, output_dir, cfg)
        det     = await self._exec(det_cmd, scan_id, "DETECTION")

        sqli_confirmed = False
        stdout_combined = det.get("stdout", "")

        if det.get("success") and _SQLI_CONFIRMED_RE.search(stdout_combined):
            sqli_confirmed = True
            logger.info(f"[{scan_id}] SQL injection confirmée — lancement extraction")

        # ── Phase 2 : extraction ───────────────────────────────────
        ext_stdout = ""
        if sqli_confirmed and ALLOW_EXTRACTION_MODE:
            ext_cmd = self._extraction_cmd(url, output_dir, cfg)
            ext     = await self._exec(ext_cmd, scan_id, "EXTRACTION")
            ext_stdout = ext.get("stdout", "")
            stdout_combined += "\n" + ext_stdout

        # ── Collecter les CSV produits par SQLMap ──────────────────
        csv_files = self._collect_csvs(output_dir, scan_id)

        return {
            "success":       det.get("success", False),
            "sqli_confirmed": sqli_confirmed,
            "stdout":        stdout_combined,
            "stderr":        det.get("stderr", ""),
            "output_dir":    str(output_dir),
            "csv_files":     csv_files,
            "duration":      det.get("duration", 0) + (ext.get("duration", 0) if sqli_confirmed and ALLOW_EXTRACTION_MODE else 0),
            "error":         det.get("error") if not det.get("success") else None,
        }

    def _collect_csvs(self, output_dir: Path, scan_id: str) -> List[str]:
        """
        Collecte les CSVs générés par SQLMap (sous dump/) et les copie dans
        REPORTS_CSV_DIR/{scan_id}/.
        Retourne la liste des chemins de destination.
        """
        dest_dir = REPORTS_CSV_DIR / scan_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        paths: List[str] = []

        for csv_path in output_dir.rglob("*.csv"):
            # Aplatir le chemin : dump/db/table.csv → db__table.csv
            rel = csv_path.relative_to(output_dir)
            parts = list(rel.parts)
            flat_name = "__".join(p for p in parts if p != "dump") if len(parts) > 1 else csv_path.name
            dest = dest_dir / flat_name
            try:
                shutil.copy2(str(csv_path), str(dest))
                paths.append(str(dest))
                logger.info(f"[{scan_id}] CSV copié → {dest}")
            except Exception as exc:
                logger.warning(f"[{scan_id}] CSV copy failed {csv_path}: {exc}")

        return paths

    def cleanup(self, scan_id: str) -> None:
        target = TEMP_DIR / scan_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            logger.info(f"[{scan_id}] Temp nettoyé")
