"""
SQL Audit Scanner - SQLMap subprocess wrapper

Pipeline 3 phases séquentielles :
  Phase 1 : Détection    — trouver les paramètres injectables
  Phase 2 : Énumération  — lister les BDs/tables (si injection confirmée)
  Phase 3 : Dump         — extraction complète   (si injection confirmée + mode activé)
"""
import asyncio
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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
    """Async wrapper autour du CLI sqlmap — 3 phases séquentielles."""

    # ── Constructeurs de commandes ─────────────────────────────────

    def _base_args(self, url: str, output_dir: Path, config: Dict[str, Any],
                   flush: bool = False) -> list:
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
            "-v", "0",
            "--no-cast",
            "--time-sec", "5",
        ]
        if flush:
            cmd.append("--flush-session")

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

    def _detect_cmd(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        """Phase 1 — tester si des paramètres sont injectables."""
        cmd = self._base_args(url, output_dir, config, flush=True)
        if config.get("test_forms", SCAN_DEFAULT_CONFIG.get("test_forms", True)):
            cmd.append("--forms")
        return cmd

    def _enumerate_cmd(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        """Phase 2 — lister BDs, tables, user courant (réutilise la session)."""
        cmd = self._base_args(url, output_dir, config, flush=False)
        cmd += [
            "--banner",
            "--current-db",
            "--current-user",
            "--dbs",
            "--tables",
        ]
        return cmd

    def _dump_cmd(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        """Phase 3 — extraction complète (réutilise la session)."""
        cmd = self._base_args(url, output_dir, config, flush=False)
        cmd += [
            "--dump-all",
            "--exclude-sysdbs",
            "--csv-del", ",",
        ]
        return cmd

    # ── Exécution ─────────────────────────────────────────────────

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
                logger.warning(f"[{scan_id}] [{label}] Timeout {SQLMAP_TIMEOUT}s")
                return {"success": False, "error": f"Timeout {label}",
                        "duration": dur, "stdout": "", "stderr": ""}

            dur = (datetime.now() - start).total_seconds()
            logger.info(f"[{scan_id}] [{label}] Done {dur:.1f}s rc={proc.returncode}")
            return {
                "success":    True,
                "returncode": proc.returncode,
                "stdout":     stdout_b.decode("utf-8", errors="replace"),
                "stderr":     stderr_b.decode("utf-8", errors="replace"),
                "duration":   dur,
            }
        except FileNotFoundError:
            logger.error(f"[{scan_id}] SQLMap introuvable : {SQLMAP_PATH}")
            return {"success": False, "error": f"SQLMap introuvable '{SQLMAP_PATH}'",
                    "duration": 0.0, "stdout": "", "stderr": ""}
        except Exception as exc:
            dur = (datetime.now() - start).total_seconds()
            logger.error(f"[{scan_id}] [{label}] Error: {exc}")
            return {"success": False, "error": str(exc), "duration": dur, "stdout": "", "stderr": ""}

    # ── API publique — 3 méthodes distinctes ──────────────────────

    async def detect_injections(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Phase 1 : détecte si des paramètres/formulaires sont injectables.
        Retourne sqli_confirmed=True si au moins une injection trouvée.
        """
        cfg = config or {}
        output_dir = TEMP_DIR / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        result = await self._exec(self._detect_cmd(url, output_dir, cfg), scan_id, "DETECT")
        stdout = result.get("stdout", "")
        sqli_confirmed = bool(result.get("success") and _SQLI_CONFIRMED_RE.search(stdout))
        if sqli_confirmed:
            logger.info(f"[{scan_id}] Injection SQL confirmée")
        else:
            logger.info(f"[{scan_id}] Aucune injection détectée")
        return {**result, "sqli_confirmed": sqli_confirmed, "output_dir": str(output_dir), "csv_files": []}

    async def enumerate_db(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Phase 2 : liste les BDs, tables, banner.
        Doit être appelée après detect_injections (réutilise la session).
        """
        cfg = config or {}
        output_dir = TEMP_DIR / scan_id
        result = await self._exec(self._enumerate_cmd(url, output_dir, cfg), scan_id, "ENUM")
        return {**result, "csv_files": []}

    async def dump_data(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Phase 3 : dump-all des tables utilisateurs.
        Doit être appelée après enumerate_db (réutilise la session).
        """
        cfg = config or {}
        output_dir = TEMP_DIR / scan_id
        result = await self._exec(self._dump_cmd(url, output_dir, cfg), scan_id, "DUMP")
        csv_files = self._collect_csvs(output_dir, scan_id)
        return {**result, "csv_files": csv_files, "output_dir": str(output_dir)}

    def _collect_csvs(self, output_dir: Path, scan_id: str) -> List[str]:
        dest_dir = REPORTS_CSV_DIR / scan_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        paths: List[str] = []
        for csv_path in output_dir.rglob("*.csv"):
            rel   = csv_path.relative_to(output_dir)
            parts = list(rel.parts)
            flat_name = "__".join(p for p in parts if p != "dump") if len(parts) > 1 else csv_path.name
            dest = dest_dir / flat_name
            try:
                shutil.copy2(str(csv_path), str(dest))
                paths.append(str(dest))
                logger.info(f"[{scan_id}] CSV → {dest}")
            except Exception as exc:
                logger.warning(f"[{scan_id}] CSV copy failed {csv_path}: {exc}")
        return paths

    def cleanup(self, scan_id: str) -> None:
        target = TEMP_DIR / scan_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            logger.info(f"[{scan_id}] Temp nettoyé")
