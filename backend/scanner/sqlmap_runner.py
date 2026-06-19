"""
SQL Audit Scanner - SQLMap subprocess wrapper

Runs SQLMap in non-interactive, read-only audit mode.
No data extraction beyond what is needed to confirm a vulnerability.

Configurable parameters per scan request:
  user_agent, headers, cookies, auth_bearer,
  timeout, threads, level, risk, techniques, test_forms, smart_mode
"""
import asyncio
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR, SCAN_DEFAULT_CONFIG, SQLMAP_PATH, SQLMAP_TIMEOUT, TEMP_DIR
from backend.utils.logger import setup_logger
from backend.utils.validators import mask_secrets

logger = setup_logger("sqlmap_runner", LOGS_DIR / "scanner.log")


class SQLMapRunner:
    """Async wrapper around the sqlmap CLI."""

    def _build_command(self, url: str, output_dir: Path, config: Dict[str, Any]) -> list:
        """
        Build an audit-focused sqlmap command from a merged config dict.

        Safety constraints always enforced:
          --batch  : non-interactive, no prompts
          risk ≤ 2 : no UPDATE/DELETE/DROP payloads (risk 3 disabled)
        """
        cfg = {**SCAN_DEFAULT_CONFIG, **{k: v for k, v in config.items() if v is not None}}

        # Clamp parameters to safe ranges
        level    = max(1, min(int(cfg.get("level", 2)),    5))
        risk     = max(1, min(int(cfg.get("risk", 1)),     2))   # cap at 2 for audit
        threads  = max(1, min(int(cfg.get("threads", 3)), 10))
        timeout  = max(10, min(int(cfg.get("timeout", 30)), 120))
        techs    = str(cfg.get("techniques", "BEUSTQ")).upper() or "BEUSTQ"

        cmd = [
            SQLMAP_PATH,
            "-u", url,
            "--batch",
            "--output-dir", str(output_dir),
            "--level", str(level),
            "--risk",  str(risk),
            "--timeout", str(timeout),
            "--retries", "2",
            "--threads", str(threads),
            "--technique", techs,
            "--flush-session",
            "-v", "2",
            # Detection proof — read-only queries only
            "--banner",
            "--current-db",
            "--current-user",
            "--dbs",
        ]

        if cfg.get("test_forms", True):
            cmd.append("--forms")

        if cfg.get("smart_mode", True):
            cmd.append("--smart")

        # Optional HTTP identity
        user_agent = str(cfg.get("user_agent", "")).strip()
        if user_agent:
            cmd += ["--user-agent", user_agent]

        cookies = str(cfg.get("cookies", "")).strip()
        if cookies:
            cmd += ["--cookie", cookies]

        auth_bearer = str(cfg.get("auth_bearer", "")).strip()
        if auth_bearer:
            cmd += ["--headers", f"Authorization: Bearer {auth_bearer}"]

        # Custom headers — accept either dict or multiline "Key: Value" string
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

    # ──────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────

    async def run_scan(
        self,
        url: str,
        scan_id: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an async sqlmap scan.

        Returns a dict:
          success, stdout, stderr, returncode, output_dir, duration, error
        """
        if config is None:
            config = {}

        output_dir = TEMP_DIR / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(url, output_dir, config)
        start = datetime.now()

        # Never log raw secrets
        cmd_safe = " ".join(str(c) for c in cmd)
        logger.info(f"[{scan_id}] Launching: {mask_secrets(cmd_safe)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=SQLMAP_TIMEOUT
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                dur = (datetime.now() - start).total_seconds()
                logger.warning(f"[{scan_id}] Timeout after {SQLMAP_TIMEOUT}s")
                return {
                    "success": False,
                    "error": f"Scan interrompu après {SQLMAP_TIMEOUT} secondes (timeout)",
                    "output_dir": str(output_dir),
                    "duration": dur,
                }

            dur = (datetime.now() - start).total_seconds()
            logger.info(f"[{scan_id}] Done in {dur:.1f}s (rc={proc.returncode})")

            return {
                "success": True,
                "returncode": proc.returncode,
                "stdout": stdout_b.decode("utf-8", errors="replace"),
                "stderr": stderr_b.decode("utf-8", errors="replace"),
                "output_dir": str(output_dir),
                "duration": dur,
            }

        except FileNotFoundError:
            logger.error(f"[{scan_id}] SQLMap not found at: {SQLMAP_PATH}")
            return {
                "success": False,
                "error": (
                    f"SQLMap introuvable à '{SQLMAP_PATH}'. "
                    "Installez-le (apt install sqlmap) ou définissez SQLMAP_PATH."
                ),
                "output_dir": str(output_dir),
                "duration": 0.0,
            }
        except Exception as exc:
            dur = (datetime.now() - start).total_seconds()
            logger.error(f"[{scan_id}] Unexpected error: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "output_dir": str(output_dir),
                "duration": dur,
            }

    def cleanup(self, scan_id: str) -> None:
        """Delete all temporary files produced by this scan."""
        target = TEMP_DIR / scan_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            logger.info(f"[{scan_id}] Temp directory removed")
