"""
Passive SQL Injection module.

Probes URL query parameters with a single quote and inspects the response
body for SQL error signatures. Detection only — no data extraction.
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.scanner.modules.base_module import BaseModule

_SQL_ERROR_PATTERNS = [
    r"You have an error in your SQL syntax",
    r"Warning.*mysql_",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQLSTATE\[",
    r"ORA-\d{4,5}",
    r"PG::SyntaxError",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Microsoft SQL Native Client",
    r"ODBC.*Driver.*Error",
    r"SQLiteException",
    r"DB2 SQL error",
    r"CLI Driver.*DB2",
    r"org\.postgresql\.util\.PSQLException",
    r"com\.mysql\.jdbc\.exceptions",
    r"java\.sql\.SQLException",
    r"Sybase message",
    r"net\.sourceforge\.jtds",
    r"supplied argument is not a valid MySQL result",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SQL_ERROR_PATTERNS]


class SQLInjectionPassiveModule(BaseModule):
    NAME     = "sql_injection_passive"
    CATEGORY = "SQL Injection"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if not params:
            await self._check_base_response(url, findings)
            return findings

        for idx, (name, _) in enumerate(params):
            probe_params = list(params)
            probe_params[idx] = (name, "'" + probe_params[idx][1])
            probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))

            try:
                resp = await self._client.get(probe_url)
                body = resp.text[:8000]
                for pat in _COMPILED:
                    m = pat.search(body)
                    if m:
                        self._log.warning(f"SQL error in param '{name}' at {url}")
                        findings.append(self._finding(
                            type="sql_error_exposed",
                            severity="high",
                            confidence="confirmed",
                            description=f"Message d'erreur SQL exposé — paramètre « {name} »",
                            url=url,
                            location=probe_url,
                            evidence=m.group(0)[:300],
                            impact=(
                                "Le message d'erreur révèle la structure interne de la base "
                                "et confirme qu'une injection est potentiellement exploitable."
                            ),
                            recommendation=(
                                "Utiliser des requêtes paramétrées. Désactiver les messages "
                                "d'erreur verbeux en production. Configurer des pages d'erreur génériques."
                            ),
                        ))
                        break
            except Exception as exc:
                self._log.debug(f"Probe error for param '{name}': {exc}")

        return findings

    async def _check_base_response(self, url: str, findings: List[Dict]) -> None:
        try:
            resp = await self._client.get(url)
            body = resp.text[:8000]
            for pat in _COMPILED:
                m = pat.search(body)
                if m:
                    findings.append(self._finding(
                        type="sql_error_in_base_response",
                        severity="high",
                        confidence="confirmed",
                        description="Message d'erreur SQL présent dans la réponse de base",
                        url=url,
                        evidence=m.group(0)[:300],
                        impact=(
                            "Des erreurs SQL sont visibles sans injection active, "
                            "indiquant une divulgation d'informations sur la base de données."
                        ),
                        recommendation=(
                            "Désactiver les messages d'erreur verbeux. "
                            "Utiliser des gestionnaires d'exceptions génériques."
                        ),
                    ))
                    break
        except Exception:
            pass
