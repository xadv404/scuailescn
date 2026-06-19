"""
Passive scanner orchestrator.

Runs all detection modules concurrently via asyncio.gather.
Reports per-module progress through an optional callback.
"""
import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

from backend.scanner.core.http_client import AuditHttpClient
from backend.scanner.modules.api_risks       import APIRisksModule
from backend.scanner.modules.auth_risks      import AuthRisksModule
from backend.scanner.modules.config_security import ConfigSecurityModule
from backend.scanner.modules.db_exposure     import DBExposureModule
from backend.scanner.modules.info_disclosure import InfoDisclosureModule
from backend.scanner.modules.input_validation import InputValidationModule
from backend.scanner.modules.sql_injection   import SQLInjectionPassiveModule

_MODULE_CLASSES = [
    SQLInjectionPassiveModule,
    InfoDisclosureModule,
    InputValidationModule,
    APIRisksModule,
    AuthRisksModule,
    DBExposureModule,
    ConfigSecurityModule,
]

_log = logging.getLogger("passive_scanner")


async def run_passive_scan(
    url: str,
    config: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Run all passive modules against *url* concurrently.

    progress_callback(module_name, completed_count, total_count) is called
    immediately after each module finishes so the caller can update the UI.
    """
    total     = len(_MODULE_CLASSES)
    completed = 0
    lock      = asyncio.Lock()

    async with AuditHttpClient(config or {}) as client:
        modules = [Cls(client) for Cls in _MODULE_CLASSES]

        async def _run(module) -> List[Dict[str, Any]]:
            nonlocal completed
            try:
                result = await module.scan(url)
            except Exception as exc:
                _log.error(f"Module {module.NAME} raised: {exc}")
                result = []
            async with lock:
                completed += 1
                if progress_callback:
                    try:
                        progress_callback(module.NAME, completed, total)
                    except Exception:
                        pass
            return result

        results = await asyncio.gather(*[_run(m) for m in modules])

    all_findings: List[Dict[str, Any]] = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
    return all_findings
