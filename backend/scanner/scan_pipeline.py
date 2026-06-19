"""
Central scan pipeline orchestrator.

Manages execution order, parallel module runs, error handling,
result centralization, and progress reporting.

Flow:
  1. Recon (sensitive_data, authentication)
  2. Injection probes (injection, xss_csrf, database_security)
  3. Access control (access_control)
  4. API & file checks (api_security, file_security)
  5. Result aggregation → risk scoring → report
"""
import asyncio
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from backend.core.http_client import AuditHttpClient
from backend.core.analyzer import (
    build_recommendations,
    build_scan_summary,
    calculate_risk_score,
    deduplicate,
    sort_by_severity,
)
from backend.scanner.modules.access_control    import AccessControlModule
from backend.scanner.modules.api_security      import APISecurityModule
from backend.scanner.modules.authentication    import AuthenticationModule
from backend.scanner.modules.database_security import DatabaseSecurityModule
from backend.scanner.modules.file_security     import FileSecurityModule
from backend.scanner.modules.injection         import InjectionModule
from backend.scanner.modules.sensitive_data    import SensitiveDataModule
from backend.scanner.modules.xss_csrf         import XssCsrfModule

# Ordered execution groups (each group runs in parallel internally)
_PHASE_1 = [SensitiveDataModule, AuthenticationModule]
_PHASE_2 = [InjectionModule, XssCsrfModule, DatabaseSecurityModule]
_PHASE_3 = [AccessControlModule]
_PHASE_4 = [APISecurityModule, FileSecurityModule]

_ALL_PHASES = [_PHASE_1, _PHASE_2, _PHASE_3, _PHASE_4]
_PHASE_NAMES = [
    "Reconnaissance passive",
    "Détection d'injections",
    "Contrôle d'accès",
    "API & fichiers",
]

# Progress range reserved for module scan phases (5% – 85%)
_PCT_START = 5
_PCT_END   = 85


ProgressCallback = Callable[[str, int, int], None]


async def _run_module_safe(
    module_cls: type,
    client: AuditHttpClient,
    url: str,
) -> List[Dict[str, Any]]:
    """Instantiate and run a module; return [] on any error."""
    try:
        mod = module_cls(client)
        return await mod.scan(url)
    except Exception as exc:
        import logging
        logging.getLogger("pipeline").warning(
            f"Module {module_cls.__name__} failed: {exc}"
        )
        return []


async def run_audit_pipeline(
    url: str,
    config: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[ProgressCallback] = None,
    *,
    timeout_per_phase: int = 120,
) -> Dict[str, Any]:
    """
    Run all audit modules in phased parallel execution.

    Returns a dict with:
      - findings (List[Dict])
      - risk_score (int)
      - risk_level (str)
      - summary (Dict)
      - recommendations (List[Dict])
      - phases (List[Dict])  — per-phase timing and finding counts
      - duration_s (float)
    """
    cfg       = config or {}
    findings: List[Dict[str, Any]] = []
    phases_meta: List[Dict[str, Any]] = []
    total_phases = len(_ALL_PHASES)
    t_start  = time.monotonic()

    def _cb(msg: str, pct: int) -> None:
        if progress_callback:
            # Use signature (module_name_or_msg, done_pct, 100)
            progress_callback(msg, pct, 100)

    _cb("Initialisation du pipeline…", _PCT_START)

    async with AuditHttpClient(config=cfg) as client:
        for phase_idx, phase_modules in enumerate(_ALL_PHASES):
            phase_name = _PHASE_NAMES[phase_idx]
            phase_pct_start = _PCT_START + round(
                (phase_idx / total_phases) * (_PCT_END - _PCT_START)
            )
            phase_pct_end = _PCT_START + round(
                ((phase_idx + 1) / total_phases) * (_PCT_END - _PCT_START)
            )
            _cb(f"Phase {phase_idx + 1}/{total_phases} — {phase_name}…", phase_pct_start)

            phase_t0 = time.monotonic()
            tasks = [
                asyncio.create_task(_run_module_safe(cls, client, url))
                for cls in phase_modules
            ]

            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout_per_phase,
                )
            except asyncio.TimeoutError:
                results = [[] for _ in phase_modules]

            phase_findings: List[Dict[str, Any]] = []
            for res in results:
                if isinstance(res, list):
                    phase_findings.extend(res)

            findings.extend(phase_findings)
            phase_duration = round(time.monotonic() - phase_t0, 1)
            phases_meta.append({
                "name":      phase_name,
                "modules":   [cls.NAME for cls in phase_modules],
                "findings":  len(phase_findings),
                "duration_s": phase_duration,
            })
            _cb(f"Phase {phase_idx + 1} terminée ({len(phase_findings)} résultats)", phase_pct_end)

    # Deduplicate and sort
    findings = deduplicate(findings)
    findings = sort_by_severity(findings)

    risk_score = calculate_risk_score(findings)

    # Detect technologies from findings evidence
    technologies = _extract_technologies(findings)
    database_type = _detect_db(findings)

    summary = build_scan_summary(
        findings=findings,
        database_type=database_type,
        technologies=technologies,
        risk_score=risk_score,
        scan_type="audit",
    )
    recommendations = build_recommendations(findings)

    _cb("Pipeline terminé — génération du rapport…", _PCT_END)

    return {
        "findings":        findings,
        "risk_score":      risk_score,
        "risk_level":      summary["risk_level"],
        "summary":         summary,
        "recommendations": recommendations,
        "phases":          phases_meta,
        "duration_s":      round(time.monotonic() - t_start, 1),
        "technologies":    technologies,
        "database_type":   database_type,
    }


def _extract_technologies(findings: List[Dict[str, Any]]) -> List[str]:
    techs: List[str] = []
    combined = " ".join(
        str(f.get("evidence", "")) + " " + str(f.get("description", ""))
        for f in findings
    ).lower()
    for tech, keywords in (
        ("PHP",       ["php", "x-powered-by: php"]),
        ("WordPress", ["wordpress", "wp-content", "wp-admin"]),
        ("Drupal",    ["drupal", "x-drupal"]),
        ("Nginx",     ["nginx"]),
        ("Apache",    ["apache"]),
        ("Node.js",   ["express", "node.js", "x-powered-by: express"]),
        ("Django",    ["django", "csrfmiddlewaretoken"]),
        ("Laravel",   ["laravel", "x-powered-by: laravel"]),
        ("ASP.NET",   ["asp.net", "x-aspnet-version", "x-aspnetmvc"]),
        ("Spring",    ["org.springframework", "java", "javax.servlet"]),
        ("Ruby",      ["rack", "ruby", "rails"]),
    ):
        if any(kw in combined for kw in keywords) and tech not in techs:
            techs.append(tech)
    return techs


def _detect_db(findings: List[Dict[str, Any]]) -> Optional[str]:
    combined = " ".join(
        str(f.get("evidence", "")) + " " + str(f.get("description", ""))
        for f in findings
    ).lower()
    for db, keywords in (
        ("MariaDB",     ["mariadb"]),
        ("MySQL",       ["mysql", "you have an error in your sql syntax"]),
        ("PostgreSQL",  ["postgresql", "pg::", "pgsql"]),
        ("Oracle",      ["ora-", "oracle"]),
        ("MSSQL",       ["mssql", "microsoft ole db", "sql server"]),
        ("SQLite",      ["sqlite"]),
        ("MongoDB",     ["mongodb", "mongoclient", "_id"]),
    ):
        if any(kw in combined for kw in keywords):
            return db
    return None
