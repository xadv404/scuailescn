"""
Pipeline de pentest automatisé.

Flow pour chaque cible :
  1. Pré-filtre SQLi rapide  (2-8 s)  → décision go/no-go pour SQLMap
  2. Recon passif            (parallel avec étape 1)
  3. SQLMap dump             (uniquement sur candidates — detect+dump en 1 passe)
  4. Analyse & export CSV
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
from backend.scanner.modules.sqli_prefilter   import sqli_prefilter

_PHASE_1 = [SensitiveDataModule, AuthenticationModule]
_PHASE_2 = [InjectionModule, XssCsrfModule, DatabaseSecurityModule]
_PHASE_3 = [AccessControlModule]
_PHASE_4 = [APISecurityModule, FileSecurityModule]
_ALL_PHASES  = [_PHASE_1, _PHASE_2, _PHASE_3, _PHASE_4]
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
    findings: List[Dict[str, Any]] = []
    phases_meta: List[Dict[str, Any]] = []

    def _cb(msg: str, pct: int) -> None:
        if progress_callback:
            progress_callback(msg, pct, 100)

    async with AuditHttpClient(config=config) as client:
        for idx, phase_modules in enumerate(_ALL_PHASES):
            name     = _PHASE_NAMES[idx]
            pct_base = 5  + round((idx / len(_ALL_PHASES)) * 40)
            pct_end  = 5  + round(((idx + 1) / len(_ALL_PHASES)) * 40)
            _cb(f"Recon {idx+1}/{len(_ALL_PHASES)} — {name}…", pct_base)

            t0    = time.monotonic()
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
    cfg     = config or {}
    t_start = time.monotonic()

    def _cb(msg: str, pct: int) -> None:
        if progress_callback:
            progress_callback(msg, pct, 100)

    _cb("Initialisation…", 3)

    # ══ PHASES 1+2 — Pré-filtre SQLi + recon passif EN PARALLÈLE ══
    _cb("Pré-filtre SQLi & scan vulnérabilités en parallèle…", 5)

    prefilter_task = asyncio.create_task(sqli_prefilter(url, timeout=8.0))
    passive_task   = asyncio.create_task(
        run_passive_phases(url, cfg, progress_callback=None, timeout_per_phase=90)
    )

    prefilter_result = await prefilter_task
    passive_result   = await passive_task

    candidate   = prefilter_result.get("candidate", False)
    confidence  = prefilter_result.get("confidence", "none")
    pf_reasons  = prefilter_result.get("reasons", [])

    _cb(
        f"Pré-filtre : {'candidat SQLi (' + confidence + ')' if candidate else 'aucun vecteur — SQLMap ignoré'}",
        52,
    )

    # ══ PHASE 3 — SQLMap dump (uniquement sur candidats) ══════════
    sqlmap_result: Dict[str, Any] = {
        "success": False, "sqli_confirmed": False,
        "stdout": "", "stderr": "", "output_dir": "", "csv_files": [],
    }

    if candidate and sqlmap_runner:
        # Extraire un hint SGBD depuis le pré-filtre si possible
        db_hint = _db_hint_from_reasons(pf_reasons)
        _cb(f"SQLMap dump en cours{' [' + db_hint + ']' if db_hint else ''}…", 55)
        sqlmap_result = await sqlmap_runner.run_scan(
            url, scan_id, config=cfg, db_hint=db_hint,
        )
        sqli_label = "SQLi confirmée ✓" if sqlmap_result.get("sqli_confirmed") else "SQLi non confirmée"
        _cb(f"SQLMap terminé — {sqli_label}", 80)
    else:
        _cb("SQLMap ignoré (pas de vecteur d'injection)", 80)

    # ── Fusion des findings ────────────────────────────────────────
    _cb("Analyse et fusion…", 83)

    all_findings: List[Dict[str, Any]] = list(passive_result.get("findings", []))

    if sqlmap_result.get("success") and sqlmap_result.get("stdout"):
        try:
            from backend.scanner.analyzer import ResultAnalyzer
            _ana      = ResultAnalyzer()
            stdout    = sqlmap_result.get("stdout", "")
            out_dir   = sqlmap_result.get("output_dir", "")
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

    risk_score    = calculate_risk_score(all_findings)
    technologies  = _extract_technologies(all_findings, sqlmap_result)
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
    summary["prefilter"] = {
        "candidate":  candidate,
        "confidence": confidence,
        "reasons":    pf_reasons,
    }

    recommendations = build_recommendations(all_findings)
    sqli_confirmed  = sqlmap_result.get("sqli_confirmed", False)

    # ── Export CSV ────────────────────────────────────────────────
    _cb("Export CSV…", 87)
    from backend.scanner.csv_exporter import (
        export_findings_csv, export_summary_csv, list_csv_files,
    )
    duration_s = round(time.monotonic() - t_start, 1)
    csv_files: List[str] = []

    fc = export_findings_csv(all_findings, scan_id, url)
    if fc:
        csv_files.append(fc)

    csv_files.extend(sqlmap_result.get("csv_files", []))

    sc = export_summary_csv(
        scan_id=scan_id, url=url,
        risk_score=risk_score, risk_level=summary["risk_level"],
        findings=all_findings, sqli_confirmed=sqli_confirmed,
        database_type=database_type, technologies=technologies,
        duration_s=duration_s, csv_data_files=sqlmap_result.get("csv_files", []),
    )
    if sc:
        csv_files.append(sc)

    _cb("Pipeline terminé", 92)

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
        "prefilter":       prefilter_result,
    }


# ── Helpers ────────────────────────────────────────────────────

def _db_hint_from_reasons(reasons: List[str]) -> Optional[str]:
    combined = " ".join(reasons).lower()
    for db, kws in (
        ("mysql",      ["mysql", "mariadb"]),
        ("postgresql", ["pgsql", "postgresql", "pg::"]),
        ("mssql",      ["mssql", "microsoft sql", "ole db"]),
        ("oracle",     ["ora-", "oracle"]),
        ("sqlite",     ["sqlite"]),
    ):
        if any(kw in combined for kw in kws):
            return db
    return None


def _extract_technologies(findings: List[Dict], sqlmap_result: Dict) -> List[str]:
    techs: List[str] = []
    combined = (
        " ".join(str(f.get("evidence", "")) + " " + str(f.get("description", "")) for f in findings)
        + " " + sqlmap_result.get("stdout", "")
    ).lower()
    for tech, keywords in (
        ("PHP",        ["php", "x-powered-by: php"]),
        ("WordPress",  ["wordpress", "wp-content", "wp-admin"]),
        ("Drupal",     ["drupal"]),
        ("Nginx",      ["nginx"]),
        ("Apache",     ["apache"]),
        ("Node.js",    ["express", "node.js"]),
        ("Django",     ["django", "csrfmiddlewaretoken"]),
        ("Laravel",    ["laravel"]),
        ("ASP.NET",    ["asp.net", "x-aspnet-version"]),
        ("Spring",     ["org.springframework", "javax.servlet"]),
        ("Ruby/Rails", ["rack", "rails"]),
        ("Tomcat",     ["tomcat", "catalina"]),
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
