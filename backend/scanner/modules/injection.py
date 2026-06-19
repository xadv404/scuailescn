"""
Injection module.

Detects:
  - SQL Injection (passive error-based)
  - NoSQL Injection (MongoDB operator payloads)
  - Server-Side Template Injection (SSTI)
  - Command Injection indicators
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.scanner.modules.base_module import BaseModule

_SQL_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQLSTATE\[",
        r"ORA-\d{4,5}",
        r"PG::SyntaxError",
        r"Microsoft OLE DB Provider",
        r"SQLiteException",
        r"DB2 SQL error",
    ]
]

_NOSQL_PAYLOADS = [
    ("[$ne]", "not-equal operator"),
    ("[$gt]", "greater-than operator"),
    ("[$regex]", "regex operator"),
]

_NOSQL_SUCCESS_SIGNS = [
    re.compile(r'"_id":', re.IGNORECASE),
    re.compile(r'"results?":\s*\[', re.IGNORECASE),
    re.compile(r'"data":\s*\[', re.IGNORECASE),
    re.compile(r'MongoError', re.IGNORECASE),
    re.compile(r'CastError', re.IGNORECASE),
]

_SSTI_MARKER = "__SSTI49__"
_SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"]
_SSTI_RESULT  = re.compile(r"49|__SSTI49__", re.IGNORECASE)

_CMD_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"sh: .+: command not found",
        r"/bin/sh: ",
        r"cmd\.exe",
        r"'ping' is not recognized",
        r"PING \d+\.\d+\.\d+\.\d+",
        r"uid=\d+\(.+\) gid=\d+",
    ]
]


class InjectionModule(BaseModule):
    NAME     = "injection"
    CATEGORY = "Injection"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        for idx, (pname, pval) in enumerate(params):
            # ── SQL Injection (single-quote) ────────────────────
            sqli_params = list(params)
            sqli_params[idx] = (pname, "'" + pval)
            sqli_url = urlunparse(parsed._replace(query=urlencode(sqli_params)))
            try:
                resp = await self._client.get(sqli_url)
                for pat in _SQL_ERROR_PATTERNS:
                    m = pat.search(resp.text[:8000])
                    if m:
                        findings.append(self._finding(
                            name="sql_injection_error_based",
                            severity="high",
                            confidence="confirmed",
                            description=f"SQL Injection (error-based) — paramètre « {pname} »",
                            url=url,
                            location=sqli_url,
                            evidence=m.group(0)[:300],
                            impact=(
                                "Un attaquant peut extraire des données, contourner "
                                "l'authentification ou, selon la configuration, exécuter des "
                                "commandes système."
                            ),
                            recommendation=(
                                "Utiliser des requêtes paramétrées (prepared statements). "
                                "Valider et filtrer toutes les entrées utilisateur. "
                                "Appliquer le principe de moindre privilège au compte DB."
                            ),
                        ))
                        break
            except Exception:
                pass

            # ── NoSQL Injection ────────────────────────────────────
            for suffix, label in _NOSQL_PAYLOADS:
                nosql_params = [(k, v) for k, v in params]
                nosql_params[idx] = (pname + suffix, "1")
                nosql_url = urlunparse(parsed._replace(query=urlencode(nosql_params)))
                try:
                    baseline = await self._client.get(url)
                    resp     = await self._client.get(nosql_url)
                    if (resp.status_code == 200
                            and resp.text[:500] != baseline.text[:500]):
                        for pat in _NOSQL_SUCCESS_SIGNS:
                            if pat.search(resp.text[:4000]):
                                findings.append(self._finding(
                                    name="nosql_injection",
                                    severity="high",
                                    confidence="medium",
                                    description=f"NoSQL Injection potentielle ({label}) — paramètre « {pname} »",
                                    url=url,
                                    location=nosql_url,
                                    evidence=f"Payload {suffix} — réponse différente de la baseline",
                                    impact=(
                                        "Contournement possible de requêtes NoSQL, "
                                        "accès non autorisé à des données."
                                    ),
                                    recommendation=(
                                        "Valider et typer les entrées utilisateur avant "
                                        "utilisation dans des requêtes NoSQL. "
                                        "Utiliser des ORM/ODM avec requêtes structurées."
                                    ),
                                ))
                                break
                except Exception:
                    pass

            # ── SSTI ───────────────────────────────────────────────
            for payload in _SSTI_PAYLOADS:
                ssti_params = list(params)
                ssti_params[idx] = (pname, payload)
                ssti_url = urlunparse(parsed._replace(query=urlencode(ssti_params)))
                try:
                    resp = await self._client.get(ssti_url)
                    body = resp.text[:6000]
                    if "49" in body and payload not in body:
                        findings.append(self._finding(
                            name="ssti_detected",
                            severity="critical",
                            confidence="high",
                            description=f"Server-Side Template Injection — paramètre « {pname} » avec {payload!r}",
                            url=url,
                            location=ssti_url,
                            evidence=f"Payload {payload!r} → résultat '49' trouvé dans la réponse",
                            impact=(
                                "SSTI peut permettre l'exécution de code arbitraire "
                                "sur le serveur (RCE), lecture de fichiers et pivoting."
                            ),
                            recommendation=(
                                "Ne jamais interpoler des entrées utilisateur dans des templates. "
                                "Utiliser un moteur de template sécurisé avec sandbox activé. "
                                "Valider et assainir toutes les entrées."
                            ),
                        ))
                        break
                except Exception:
                    pass

            # ── Command Injection (error-based) ────────────────────
            cmd_payloads = [
                (pval + "; id", "semicolon"),
                (pval + "| id", "pipe"),
                (pval + "&& id", "AND"),
            ]
            for cmd_payload, label in cmd_payloads:
                cmd_params = list(params)
                cmd_params[idx] = (pname, cmd_payload)
                cmd_url = urlunparse(parsed._replace(query=urlencode(cmd_params)))
                try:
                    resp = await self._client.get(cmd_url)
                    for pat in _CMD_ERROR_PATTERNS:
                        m = pat.search(resp.text[:4000])
                        if m:
                            findings.append(self._finding(
                                name="command_injection_detected",
                                severity="critical",
                                confidence="high",
                                description=f"Command Injection possible ({label}) — paramètre « {pname} »",
                                url=url,
                                location=cmd_url,
                                evidence=m.group(0)[:200],
                                impact=(
                                    "Exécution de commandes système arbitraires sur le serveur — "
                                    "compromission totale possible."
                                ),
                                recommendation=(
                                    "Ne jamais passer des entrées utilisateur à des fonctions "
                                    "d'exécution système (exec, system, shell_exec). "
                                    "Utiliser des API spécialisées avec arguments séparés."
                                ),
                            ))
                            break
                except Exception:
                    pass

        return self._dedup(findings)
