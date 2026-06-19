"""
SQL Audit Scanner - Result analyser

Parses sqlmap stdout and output-directory files to extract structured findings.
Only technical proof-of-concept details are retained; no actual data is stored.
"""
import re
from pathlib import Path
from typing import Any, Dict, List

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import LOGS_DIR
from backend.utils.logger import setup_logger

logger = setup_logger("analyzer", LOGS_DIR / "scanner.log")

# ---------------------------------------------------------------------------
# Vulnerability catalogue
# Each entry maps to a detection regex list + CVSS-aligned metadata.
# ---------------------------------------------------------------------------
VULN_CATALOGUE: Dict[str, Dict[str, Any]] = {
    "sql_injection_generic": {
        "patterns": [
            r"parameter\s+'[^']+'\s+is\s+vulnerable",
            r"sqlmap identified the following injection point",
            r"might be injectable",
        ],
        "severity": "critical",
        "description": "SQL Injection vulnerability confirmed",
        "impact": (
            "An attacker can read, modify, or delete arbitrary database content, "
            "bypass authentication controls, or in some configurations execute "
            "operating-system commands."
        ),
        "recommendation": (
            "Replace all dynamic SQL query construction with parameterised queries "
            "or prepared statements. Validate and whitelist all user-supplied input. "
            "Apply the principle of least privilege to the database account."
        ),
    },
    "boolean_blind_sqli": {
        "patterns": [r"boolean-based blind"],
        "severity": "critical",
        "description": "Boolean-based Blind SQL Injection detected",
        "impact": (
            "The attacker can infer the full database content bit-by-bit through "
            "true/false application responses, without requiring visible error output."
        ),
        "recommendation": (
            "Use parameterised queries. Suppress detailed conditional differences "
            "in HTTP responses. Add rate-limiting to slow down inference attacks."
        ),
    },
    "time_based_blind_sqli": {
        "patterns": [r"time-based blind"],
        "severity": "critical",
        "description": "Time-based Blind SQL Injection detected",
        "impact": (
            "The attacker can extract data by measuring response delays induced by "
            "sleep-style SQL functions, making the attack invisible to simple WAF rules."
        ),
        "recommendation": (
            "Use parameterised queries. Apply strict input validation. "
            "Monitor abnormally slow database queries."
        ),
    },
    "error_based_sqli": {
        "patterns": [r"error-based"],
        "severity": "high",
        "description": "Error-based SQL Injection detected",
        "impact": (
            "Database engine error messages are being returned to the user, leaking "
            "schema information that an attacker can exploit to extract data."
        ),
        "recommendation": (
            "Use parameterised queries. Configure the application to show generic "
            "error pages. Disable verbose database error propagation in production."
        ),
    },
    "stacked_queries_sqli": {
        "patterns": [r"stacked queries"],
        "severity": "critical",
        "description": "Stacked-query SQL Injection detected",
        "impact": (
            "The attacker can execute arbitrary additional SQL statements, enabling "
            "data manipulation, schema changes, or (on some DBMS) system command execution."
        ),
        "recommendation": (
            "Use parameterised queries. Restrict database user to SELECT only where "
            "possible. Enable WAF rules targeting stacked-query patterns."
        ),
    },
    "union_based_sqli": {
        "patterns": [r"UNION query"],
        "severity": "high",
        "description": "UNION-based SQL Injection detected",
        "impact": (
            "The attacker can append UNION SELECT clauses to retrieve data from any "
            "table accessible to the database account."
        ),
        "recommendation": (
            "Use parameterised queries. Restrict database permissions. "
            "Validate and sanitise all input before use in SQL."
        ),
    },
    "out_of_band_sqli": {
        "patterns": [r"out-of-band"],
        "severity": "critical",
        "description": "Out-of-band SQL Injection channel detected",
        "impact": (
            "Data can be exfiltrated through DNS or HTTP requests to an attacker-controlled "
            "server, bypassing response-based detection."
        ),
        "recommendation": (
            "Use parameterised queries. Restrict outbound network access from the database "
            "server. Monitor unexpected DNS queries."
        ),
    },
    "dbms_version_disclosure": {
        "patterns": [
            r"the back-end DBMS is ([^\n]{1,80})",
            r"banner:\s*'([^']{1,200})'",
        ],
        "severity": "info",
        "description": "Database version information disclosed",
        "impact": (
            "The database engine type and version are visible to the attacker, allowing "
            "targeted exploitation of known CVEs."
        ),
        "recommendation": (
            "Configure the database to suppress version strings. Keep the DBMS patched "
            "to the latest stable release."
        ),
    },
    "current_db_user_disclosed": {
        "patterns": [
            r"current database:\s+'([^']{1,100})'",
            r"current user:\s+'([^']{1,100})'",
        ],
        "severity": "medium",
        "description": "Current database name / user account retrieved",
        "impact": (
            "Schema name and service account identity are exposed, narrowing the "
            "attacker's pivot path inside the database."
        ),
        "recommendation": (
            "Apply the principle of least privilege; the web application should not "
            "connect with a DBA or superuser account."
        ),
    },
    "database_enumeration": {
        "patterns": [
            r"available databases \[\d+\]",
            r"^\[.+?\] \[INFO\] fetching database names",
        ],
        "severity": "high",
        "description": "Full database enumeration succeeded",
        "impact": (
            "The attacker obtained a complete list of databases on the server, "
            "facilitating targeted data theft."
        ),
        "recommendation": (
            "Restrict the application's database account to only its own schema. "
            "Use parameterised queries to prevent the initial injection."
        ),
    },
}


class ResultAnalyzer:
    """Parse sqlmap output into a list of structured finding dicts."""

    # Maximum number of evidence snippets kept per finding (avoid storing data)
    _MAX_EVIDENCE_SNIPPETS = 3
    # Maximum character length for any single evidence snippet
    _MAX_SNIPPET_LEN = 150

    def analyze(self, raw_output: str, url: str) -> List[Dict[str, Any]]:
        """Analyse a raw text string (stdout or log file content)."""
        findings: List[Dict[str, Any]] = []
        seen_types: set = set()

        if not raw_output:
            return findings

        for vuln_type, meta in VULN_CATALOGUE.items():
            for pattern in meta["patterns"]:
                matches = re.findall(pattern, raw_output, re.IGNORECASE | re.MULTILINE)
                if matches and vuln_type not in seen_types:
                    seen_types.add(vuln_type)
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
                    logger.info(f"Finding [{meta['severity'].upper()}] {vuln_type} @ {url}")

        return findings

    def analyze_from_dir(self, output_dir: str, url: str) -> List[Dict[str, Any]]:
        """Analyse all text/log files in the sqlmap output directory."""
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_evidence(self, pattern: str, matches: list) -> Dict[str, Any]:
        snippets = []
        for m in matches[: self._MAX_EVIDENCE_SNIPPETS]:
            raw = str(m)[: self._MAX_SNIPPET_LEN]
            # Redact long quoted strings that could be actual data
            sanitised = re.sub(r"'[^']{20,}'", "'[REDACTED]'", raw)
            snippets.append(sanitised)
        return {"matched_pattern": pattern, "occurrences": len(matches), "snippets": snippets}

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        result = []
        for f in findings:
            if f["type"] not in seen:
                seen.add(f["type"])
                result.append(f)
        return result
