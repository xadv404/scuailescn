"""
SQL Audit Scanner - Result analyser

Parses sqlmap stdout and output-directory files to produce:
  1. Structured findings (SQLi types, severities, evidence)
  2. Database engine identification
  3. Scan summary with statistics

Only sanitised proof-of-concept details are kept — no raw user data.
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR
from backend.utils.logger import setup_logger

logger = setup_logger("analyzer", LOGS_DIR / "scanner.log")


# ════════════════════════════════════════════════════════════════
# Vulnerability catalogue  (CVSS-aligned)
# ════════════════════════════════════════════════════════════════
VULN_CATALOGUE: Dict[str, Dict[str, Any]] = {
    "sql_injection_generic": {
        "patterns": [
            r"parameter\s+'[^']+'\s+is\s+vulnerable",
            r"sqlmap identified the following injection point",
            r"might be injectable",
        ],
        "severity": "critical",
        "description": "Injection SQL confirmée",
        "impact": (
            "Un attaquant peut lire, modifier ou supprimer le contenu de la base de données, "
            "contourner les contrôles d'authentification ou, selon la configuration, "
            "exécuter des commandes système."
        ),
        "recommendation": (
            "Remplacer toute construction dynamique de requêtes SQL par des requêtes "
            "paramétrées ou des procédures stockées. Valider et filtrer toutes les entrées "
            "utilisateur. Appliquer le principe de moindre privilège au compte de base de données."
        ),
    },
    "boolean_blind_sqli": {
        "patterns": [r"boolean-based blind"],
        "severity": "critical",
        "description": "Injection SQL Blind booléenne détectée",
        "impact": (
            "L'attaquant peut déduire le contenu complet de la base bit par bit via "
            "les réponses vrai/faux de l'application, sans message d'erreur visible."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Atténuer les différences conditionnelles "
            "dans les réponses HTTP. Ajouter un rate-limiting pour ralentir les attaques par inférence."
        ),
    },
    "time_based_blind_sqli": {
        "patterns": [r"time-based blind"],
        "severity": "critical",
        "description": "Injection SQL Blind temporelle détectée",
        "impact": (
            "L'attaquant extrait des données en mesurant les délais de réponse induits par "
            "des fonctions SQL de type sleep(), rendant l'attaque invisible aux WAF simples."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Valider strictement les entrées. "
            "Surveiller les requêtes base de données anormalement lentes."
        ),
    },
    "error_based_sqli": {
        "patterns": [r"error-based"],
        "severity": "high",
        "description": "Injection SQL basée sur les erreurs détectée",
        "impact": (
            "Les messages d'erreur du moteur SQL sont retournés à l'utilisateur, "
            "exposant la structure du schéma exploitable pour extraire des données."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Configurer l'application pour afficher "
            "des pages d'erreur génériques. Désactiver la propagation d'erreurs verboses en production."
        ),
    },
    "stacked_queries_sqli": {
        "patterns": [r"stacked queries"],
        "severity": "critical",
        "description": "Injection SQL par requêtes empilées détectée",
        "impact": (
            "L'attaquant peut exécuter des instructions SQL supplémentaires arbitraires, "
            "permettant la manipulation de données, les modifications de schéma ou "
            "l'exécution de commandes système sur certains SGBD."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Restreindre le compte de base de données "
            "au strict minimum (SELECT uniquement si possible). Activer des règles WAF "
            "ciblant les requêtes empilées."
        ),
    },
    "union_based_sqli": {
        "patterns": [r"UNION query"],
        "severity": "high",
        "description": "Injection SQL basée sur UNION détectée",
        "impact": (
            "L'attaquant peut ajouter des clauses UNION SELECT pour extraire des données "
            "de n'importe quelle table accessible au compte de base de données."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Restreindre les permissions de base de données. "
            "Valider et assainir toutes les entrées avant utilisation dans des requêtes SQL."
        ),
    },
    "out_of_band_sqli": {
        "patterns": [r"out-of-band"],
        "severity": "critical",
        "description": "Canal d'injection SQL hors-bande détecté",
        "impact": (
            "Les données peuvent être exfiltrées via des requêtes DNS ou HTTP vers un "
            "serveur contrôlé par l'attaquant, contournant la détection basée sur les réponses."
        ),
        "recommendation": (
            "Utiliser des requêtes paramétrées. Restreindre les accès réseau sortants "
            "du serveur de base de données. Surveiller les requêtes DNS inhabituelles."
        ),
    },
    "dbms_version_disclosure": {
        "patterns": [
            r"the back-end DBMS is ([^\n]{1,80})",
            r"banner:\s*'([^']{1,200})'",
        ],
        "severity": "info",
        "description": "Informations sur la version du SGBD divulguées",
        "impact": (
            "Le type et la version du moteur de base de données sont visibles de l'extérieur, "
            "permettant de cibler des CVE spécifiques."
        ),
        "recommendation": (
            "Configurer la base de données pour supprimer les chaînes de version. "
            "Maintenir le SGBD à jour avec les derniers correctifs de sécurité."
        ),
    },
    "current_db_user_disclosed": {
        "patterns": [
            r"current database:\s+'([^']{1,100})'",
            r"current user:\s+'([^']{1,100})'",
        ],
        "severity": "medium",
        "description": "Nom de base et compte utilisateur récupérés",
        "impact": (
            "Le nom du schéma et l'identité du compte de service sont exposés, "
            "réduisant l'effort de reconnaissance nécessaire à l'attaquant."
        ),
        "recommendation": (
            "Appliquer le principe de moindre privilège ; l'application web ne doit pas "
            "se connecter avec un compte DBA ou super-utilisateur."
        ),
    },
    "database_enumeration": {
        "patterns": [
            r"available databases \[\d+\]",
            r"\[INFO\] fetching database names",
        ],
        "severity": "high",
        "description": "Énumération complète des bases de données réussie",
        "impact": (
            "L'attaquant a obtenu la liste complète des bases de données sur le serveur, "
            "facilitant un vol de données ciblé."
        ),
        "recommendation": (
            "Restreindre le compte de l'application à son propre schéma uniquement. "
            "Utiliser des requêtes paramétrées pour prévenir l'injection initiale."
        ),
    },
}


# ════════════════════════════════════════════════════════════════
# Database engine detection signatures
# ════════════════════════════════════════════════════════════════
DB_SIGNATURES: Dict[str, List[str]] = {
    "MySQL": [
        r"back-end DBMS(?:.*?)MySQL",
        r"the back-end DBMS is MySQL",
        r"MySQL\s+[\d\.]+",
        r"\[INFO\].*MySQL",
    ],
    "MariaDB": [
        r"back-end DBMS(?:.*?)MariaDB",
        r"the back-end DBMS is MariaDB",
        r"MariaDB\s+[\d\.]+",
    ],
    "PostgreSQL": [
        r"back-end DBMS(?:.*?)PostgreSQL",
        r"the back-end DBMS is PostgreSQL",
        r"PostgreSQL\s+[\d\.]+",
    ],
    "Microsoft SQL Server": [
        r"back-end DBMS(?:.*?)Microsoft SQL Server",
        r"the back-end DBMS is Microsoft SQL Server",
        r"Microsoft SQL Server\s+[\d\.]+",
        r"\bMSSQL\b",
    ],
    "Oracle": [
        r"back-end DBMS(?:.*?)Oracle",
        r"the back-end DBMS is Oracle",
        r"Oracle Database\s+[\d\.]+",
    ],
    "SQLite": [
        r"back-end DBMS(?:.*?)SQLite",
        r"the back-end DBMS is SQLite",
        r"SQLite\s+[\d\.]+",
    ],
    "IBM DB2": [
        r"back-end DBMS(?:.*?)IBM DB2",
        r"the back-end DBMS is IBM DB2",
    ],
    "Sybase": [
        r"back-end DBMS(?:.*?)Sybase",
        r"the back-end DBMS is Sybase",
    ],
    "Firebird": [
        r"back-end DBMS(?:.*?)Firebird",
        r"the back-end DBMS is Firebird",
    ],
    "SAP MaxDB": [
        r"back-end DBMS(?:.*?)SAP MaxDB",
        r"the back-end DBMS is SAP MaxDB",
    ],
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ResultAnalyzer:
    """Parse sqlmap output into structured findings, DB type, and scan summary."""

    _MAX_EVIDENCE_SNIPPETS = 3
    _MAX_SNIPPET_LEN       = 150

    # ── Findings ──────────────────────────────────────────────────

    def analyze(self, raw_output: str, url: str) -> List[Dict[str, Any]]:
        """Parse a raw text block and return a list of finding dicts."""
        findings: List[Dict[str, Any]] = []
        seen: set = set()

        if not raw_output:
            return findings

        for vuln_type, meta in VULN_CATALOGUE.items():
            for pattern in meta["patterns"]:
                matches = re.findall(pattern, raw_output, re.IGNORECASE | re.MULTILINE)
                if matches and vuln_type not in seen:
                    seen.add(vuln_type)
                    findings.append(
                        {
                            "type": vuln_type,
                            "severity": meta["severity"],
                            "location": url,
                            "description": meta["description"],
                            "impact": meta["impact"],
                            "recommendation": meta["recommendation"],
                            "evidence": self._build_evidence(pattern, matches),
                        }
                    )
                    logger.info(f"[{url}] Finding [{meta['severity'].upper()}] {vuln_type}")

        return findings

    def analyze_from_dir(self, output_dir: str, url: str) -> List[Dict[str, Any]]:
        """Scan all .log / .txt files in the sqlmap output directory."""
        findings: List[Dict[str, Any]] = []
        path = Path(output_dir)

        if not path.exists():
            return findings

        for f in list(path.rglob("*.log")) + list(path.rglob("*.txt")):
            try:
                content = f.read_text(errors="replace")
                findings.extend(self.analyze(content, url))
            except Exception as exc:
                logger.warning(f"Could not read {f}: {exc}")

        return self._deduplicate(findings)

    def merge(
        self,
        stdout_findings: List[Dict[str, Any]],
        dir_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge two finding lists, keeping only one entry per vulnerability type."""
        merged = list(stdout_findings)
        existing = {f["type"] for f in merged}
        for f in dir_findings:
            if f["type"] not in existing:
                merged.append(f)
                existing.add(f["type"])
        return merged

    # ── Database engine detection ──────────────────────────────────

    def detect_database_type(self, raw_output: str) -> Optional[str]:
        """
        Identify the database engine from sqlmap output.
        MariaDB is checked before MySQL because it is a MySQL fork and
        sqlmap may mention both keywords.
        Returns the engine name or None if unknown.
        """
        # Priority order: MariaDB before MySQL to avoid false-positive
        priority_order = [
            "MariaDB", "MySQL", "PostgreSQL", "Microsoft SQL Server",
            "Oracle", "SQLite", "IBM DB2", "Sybase", "Firebird", "SAP MaxDB",
        ]
        for db_name in priority_order:
            patterns = DB_SIGNATURES.get(db_name, [])
            for pattern in patterns:
                if re.search(pattern, raw_output, re.IGNORECASE | re.MULTILINE):
                    logger.info(f"Database engine identified: {db_name}")
                    return db_name
        return None

    # ── Scan summary ───────────────────────────────────────────────

    def build_scan_summary(
        self,
        findings: List[Dict[str, Any]],
        database_type: Optional[str],
        risk_level: str,
    ) -> Dict[str, Any]:
        """
        Build the scan_summary block for the report.
        Mirrors the spec structure with severity breakdown and DB engine stats.
        """
        sev_count = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in sev_count:
                sev_count[sev] += 1

        db_engines: Dict[str, int] = {}
        if database_type:
            db_engines[database_type] = 1

        return {
            "total_findings":   len(findings),
            "risk_level":       risk_level,
            "database_type":    database_type or "Non détecté",
            "database_engines": db_engines,
            "severity":         sev_count,
            "vulnerable":       sev_count["critical"] > 0 or sev_count["high"] > 0,
        }

    # ── Internal helpers ───────────────────────────────────────────

    def _build_evidence(self, pattern: str, matches: list) -> Dict[str, Any]:
        snippets = []
        for m in matches[: self._MAX_EVIDENCE_SNIPPETS]:
            raw = str(m)[: self._MAX_SNIPPET_LEN]
            # Redact long quoted strings that might contain actual data
            sanitised = re.sub(r"'[^']{20,}'", "'[REDACTED]'", raw)
            snippets.append(sanitised)
        return {
            "matched_pattern": pattern,
            "occurrences": len(matches),
            "snippets": snippets,
        }

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        result = []
        for f in findings:
            if f["type"] not in seen:
                seen.add(f["type"])
                result.append(f)
        return result
