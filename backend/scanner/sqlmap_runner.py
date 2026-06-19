"""
SQL Audit Scanner - SQLMap subprocess wrapper

Runs SQLMap in non-interactive, read-only audit mode.
No data extraction beyond what is needed to confirm a vulnerability.
"""
import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR, SQLMAP_PATH, SQLMAP_TIMEOUT, TEMP_DIR
from backend.utils.logger import setup_logger

logger = setup_logger("sqlmap_runner", LOGS_DIR / "scanner.log")


class SQLMapRunner:
    """Async wrapper around the sqlmap CLI."""

    def _build_command(self, url: str, output_dir: Path) -> list:
        """
        Build a minimal, audit-focused sqlmap command.

        --batch          : never ask the user for input
        --level 2        : test cookies and query strings (no brute-force headers)
        --risk 1         : safest payload set – no UPDATE/DROP statements
        --technique BEUSTQ : test all injection families (detection only)
        --forms          : also test HTML forms on the page
        --smart          : skip non-injectable parameters early
        --banner / --current-db / --dbs : gather just enough proof of exploitability
        """
        return [
            SQLMAP_PATH,
            "-u", url,
            "--batch",
            "--output-dir", str(output_dir),
            "--forms",
            "--level", "2",
            "--risk", "1",
            "--timeout", "30",
            "--retries", "2",
            "--threads", "3",
            "--technique", "BEUSTQ",
            "--smart",
            "--flush-session",
            "-v", "2",
            "--banner",
            "--current-db",
            "--dbs",
        ]

    async def run_scan(self, url: str, scan_id: str) -> Dict[str, Any]:
        """
        Execute a sqlmap scan asynchronously.

        Returns a dict with keys:
          success (bool), stdout, stderr, returncode, output_dir, duration, error
        """
        output_dir = TEMP_DIR / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_command(url, output_dir)
        start = datetime.now()

        logger.info(f"[{scan_id}] Launching: {' '.join(cmd)}")

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
                duration = (datetime.now() - start).total_seconds()
                logger.warning(f"[{scan_id}] Timeout after {SQLMAP_TIMEOUT}s")
                return {
                    "success": False,
                    "error": f"Scan timed out after {SQLMAP_TIMEOUT} seconds",
                    "output_dir": str(output_dir),
                    "duration": duration,
                }

            duration = (datetime.now() - start).total_seconds()
            logger.info(f"[{scan_id}] Completed in {duration:.1f}s (rc={proc.returncode})")

            return {
                "success": True,
                "returncode": proc.returncode,
                "stdout": stdout_b.decode("utf-8", errors="replace"),
                "stderr": stderr_b.decode("utf-8", errors="replace"),
                "output_dir": str(output_dir),
                "duration": duration,
            }

        except FileNotFoundError:
            logger.error(f"[{scan_id}] SQLMap binary not found at: {SQLMAP_PATH}")
            return {
                "success": False,
                "error": (
                    f"SQLMap not found at '{SQLMAP_PATH}'. "
                    "Install it (apt install sqlmap) or set the SQLMAP_PATH env variable."
                ),
                "output_dir": str(output_dir),
                "duration": 0.0,
            }
        except Exception as exc:
            duration = (datetime.now() - start).total_seconds()
            logger.error(f"[{scan_id}] Unexpected error: {exc}")
            return {
                "success": False,
                "error": str(exc),
                "output_dir": str(output_dir),
                "duration": duration,
            }

    def cleanup(self, scan_id: str) -> None:
        """Delete temporary files produced by this scan."""
        target = TEMP_DIR / scan_id
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            logger.info(f"[{scan_id}] Temp directory removed")
