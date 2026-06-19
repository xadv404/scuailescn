"""
Central scan orchestrator — routes to audit or deep scan mode.
"""
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class ScannerEngine:
    """Entry point for all scans. Delegates to audit or deep scanner."""

    async def run(
        self,
        url: str,
        scan_type: str = "audit",
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Dict[str, Any]:
        config = config or {}

        if scan_type == "deep":
            from backend.scanner.deep_scanner import run_deep_scan
            return await run_deep_scan(url, config, progress_callback)

        from backend.scanner.audit_scanner import run_audit_scan
        return await run_audit_scan(url, config, progress_callback)
