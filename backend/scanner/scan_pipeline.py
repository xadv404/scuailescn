"""
Pipeline de pentest automatisé — agent mode.

Flow pour chaque cible :
  1. Recon passif    (8 modules en parallèle)
  2. SQLMap          (détection + extraction si injection confirmée)
  3. Analyse         (risk scoring, déduplication)
  4. Export CSV      (findings + données extraites)
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

# Phases du recon passif (parallèle à l'intérieur de chaque phase)
_PHASE_1 = [SensitiveDataModule, AuthenticationModule]
_PHASE_2 = [InjectionModule, XssCsrfModule, DatabaseSecurityModule]
_PHASE_3 = [AccessControlModule]
_PHASE_4 = [APISecurityModule, FileSecurityModule]
_ALL_PHASES = [_PHASE_1, _PHASE_2, _PHASE_3, _PHASE_4]
_PHASE_NAMES = ["Reconnaissance", "Injections", "Contrôle d'accès", "API & fichiers"]

ProgressCallback = Callable[[str, int, int], None]


async def _run_module_safe(cls, client, url) -> List[Dict[str, Any]]:
    try:
        return await cls(client).scan(url)
    except Exception as exc:
        import logging
        logging.getLogger("pipeline").warning(f"{cls.__name__} failed: {exc}")
        return []


async def run_passive_phases(
    url: str,
    config: Dict[str, Any],
    progress_callback: Optional[ProgressCallback] = None,
    timeout_per_phase: int = 90,
) -> Dict[str, Any]:
    """
    Exécute les 4 phases de recon passif.
    Retourne {findings, phases_meta}.
    """
    findings: List[Dict[str, Any]] = []
    phases_meta: List[Dict[str, Any]] = []
    total_phases = len(_ALL_PHASES)

    def _cb(msg: str, pct: int) -> None:
        if progress_callback:
            progress_callback(msg, pct, 100)

    async with AuditHttpClient(config=config) as client:
        for idx, phase_modules in enumerate(_ALL_PHASES):
            name     = _PHASE_NAMES[idx]
            pct_base = 5 + round((idx / total_phases) * 40)
            pct_end  = 5 + round(((idx + 1) / total_phases) * 40)
            _cb(f"Recon {idx+1}/{total_phases} — {name}…", pct_base)

            t0 = time.monotonic()
            tasks = [asyncio.create_task(_run_module_safe(cls, client, url)) for cls in phase_modules]
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout_per_phase,
                )
            except asyncio.TimeoutError:
                results = [[] for _ in phase_modules]

            phase_finds: List[Dict[str, Any]] = []
            for res in results:
                if isinstance(res, list):
                    phase_finds.extend(res)

            findings.extend(phase_finds)
            phases_meta.append({
                "name":       name,
                "modules":    [cls.NAME for cls in phase_modules],
                "findings":   len(phase_finds),
                "duration_s": round(time.monotonic() - t0, 1),
            })
            _cb(f"Phase {idx+1} — {len(phase_finds)} résultats", pct_end)

    return {"findings": findings, "phases": phases_meta}


async def run_full_pipeline(
    url: str,
    scan_id: str,
    config: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[ProgressCallback] = None,
    sqlmap_runner=None,
) -> Dict[str, Any]:
    """
    Pipeline complet pour une cible.

    Retourne :
      findings, risk_score, risk_level, summary, recommendations,
      phases, database_type, technologies, sqli_confirmed,
      csv_files, duration_s
    """
    cfg    = config or {}
    t_start = time.monotonic()

    def _cb(msg: str, pct: int) -> None:
        if progress_callback:
            progress_callback(msg, pct, 100)

    _cb("Initialisation du pipeline…", 3)

    # ── Recon passif + SQLMap en parallèle ────────────────────────
    _cb("Recon passif & SQLMap en parallèle…", 5)

    passive_task = asyncio.create_task(
        run_passive_phases(url, cfg, progress_callback=None, timeout_per_phase=90)
    )
    sqlmap_task = asyncio.create_task(
        sqlmap_runner.run_scan(url, scan_id, config=cfg)
    ) if sqlmap_runner else None

    passive_result = await passive_task
    sqlmap_result  = (await sqlmap_task) if sqlmap_task else {}

    # ── Fusion des findings ────────────────────────────────────────
    _cb("Analyse et fusion des résultats…", 60)

    all_findings: List[Dict[str, Any]] = list(passive_result.get("findings", []))

    # Importer l'analyseur SQLMap (v3, format compatible)
    if sqlmap_result.get("success"):
        try:
            from backend.scanner.analyzer import ResultAnalyzer
            _ana = ResultAnalyzer()
            stdout  = sqlmap_result.get("stdout", "")
            out_dir = sqlmap_result.get("output_dir", "")
            sql_finds = _ana.merge(
                _ana.analyze(stdout, url),
                _ana.analyze_from_dir(out_dir, url),
            )
            existing = {f.get("name", f.get("type")) for f in all_findings}
            for sf in sql_finds:
                key = sf.get("name") or sf.get("type")
                if key not in existing:
                    all_findings.append(sf)
                    existing.add(key)
        except Exception:
            pass

    all_findings = deduplicate(all_findings)
    all_findings = sort_by_severity(all_findings)

    # ── Risk scoring ───────────────────────────────────────────────
    risk_score  = calculate_risk_score(all_findings)
    technologies = _extract_technologies(all_findings, sqlmap_result)
    database_type = (
        _detect_db_from_sqlmap(sqlmap_result.get("stdout", ""))
        or _detect_db_from_findings(all_findings)
    )

    summary = build_scan_summary(
        findings=all_findings,
        database_type=database_type,
        technologies=technologies,
        risk_score=risk_score,
        scan_type="pentest",
        database_info={"phases": passive_result.get("phases", [])},
    )
    summary["phases"] = passive_result.get("phases", [])

    recommendations = build_recommendations(all_findings)
    sqli_confirmed  = sqlmap_result.get("sqli_confirmed", False)

    # ── CSV ────────────────────────────────────────────────────────
    _cb("Export CSV…", 75)
    csv_files: List[str] = []

    # CSV des findings de vulnérabilités
    from backend.scanner.csv_exporter import (
        export_findings_csv, export_summary_csv, list_csv_files,
    )
    duration_s = round(time.monotonic() - t_start, 1)

    fc = export_findings_csv(all_findings, scan_id, url)
    if fc:
        csv_files.append(fc)

    # CSVs des données extraites par SQLMap
    sqlmap_csv = sqlmap_result.get("csv_files", [])
    csv_files.extend(sqlmap_csv)

    sc = export_summary_csv(
        scan_id=scan_id, url=url,
        risk_score=risk_score, risk_level=summary["risk_level"],
        findings=all_findings, sqli_confirmed=sqli_confirmed,
        database_type=database_type, technologies=technologies,
        duration_s=duration_s, csv_data_files=sqlmap_csv,
    )
    if sc:
        csv_files.append(sc)

    _cb("Pipeline terminé", 85)

    return {
        "findings":        all_findings,
        "risk_score":      risk_score,
        "risk_level":      summary["risk_level"],
        "summary":         summary,
        "recommendations": recommendations,
        "phases":          passive_result.get("phases", []),
        "database_type":   database_type,
        "technologies":    technologies,
        "sqli_confirmed":  sqli_confirmed,
        "csv_files":       csv_files,
        "duration_s":      duration_s,
    }


# ── Helpers ────────────────────────────────────────────────────

def _extract_technologies(findings: List[Dict], sqlmap_result: Dict) -> List[str]:
    techs: List[str] = []
    combined = (
        " ".join(str(f.get("evidence", "")) + " " + str(f.get("description", "")) for f in findings)
        + " " + sqlmap_result.get("stdout", "")
    ).lower()
    for tech, keywords in (
        ("PHP",       ["php", "x-powered-by: php"]),
        ("WordPress", ["wordpress", "wp-content", "wp-admin"]),
        ("Drupal",    ["drupal"]),
        ("Nginx",     ["nginx"]),
        ("Apache",    ["apache"]),
        ("Node.js",   ["express", "node.js"]),
        ("Django",    ["django", "csrfmiddlewaretoken"]),
        ("Laravel",   ["laravel"]),
        ("ASP.NET",   ["asp.net", "x-aspnet-version"]),
        ("Spring",    ["org.springframework", "javax.servlet"]),
        ("Ruby/Rails",["rack", "rails"]),
        ("Tomcat",    ["tomcat", "catalina"]),
    ):
        if any(kw in combined for kw in keywords) and tech not in techs:
            techs.append(tech)
    return techs


def _detect_db_from_sqlmap(stdout: str) -> Optional[str]:
    s = stdout.lower()
    for db, keywords in (
        ("MariaDB",    ["mariadb"]),
        ("MySQL",      ["mysql"]),
        ("PostgreSQL", ["postgresql", "pgsql"]),
        ("Oracle",     ["ora-", "oracle"]),
        ("MSSQL",      ["mssql", "microsoft sql server"]),
        ("SQLite",     ["sqlite"]),
        ("MongoDB",    ["mongodb"]),
    ):
        if any(kw in s for kw in keywords):
            return db
    return None


def _detect_db_from_findings(findings: List[Dict]) -> Optional[str]:
    combined = " ".join(
        str(f.get("evidence", "")) + " " + str(f.get("description", ""))
        for f in findings
    ).lower()
    for db, keywords in (
        ("MariaDB",    ["mariadb"]),
        ("MySQL",      ["mysql", "you have an error in your sql syntax"]),
        ("PostgreSQL", ["postgresql", "pg::"]),
        ("Oracle",     ["ora-", "oracle"]),
        ("MSSQL",      ["mssql", "microsoft ole db"]),
        ("SQLite",     ["sqlite"]),
        ("MongoDB",    ["mongodb", "_id"]),
    ):
        if any(kw in combined for kw in keywords):
            return db
    return None
