"""
Injection module.

Detects:
  - SQL Injection (error-based GET + POST, boolean-blind GET)
  - NoSQL Injection (MongoDB operator payloads)
  - Server-Side Template Injection (SSTI)
  - Command Injection indicators
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

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
        # SQLite / Python
        r"unrecognized token",
        r"near ['\"].+?['\"]: syntax error",
        r"sqlite3\.\w+Error",
        r"OperationalError:",
        # PDO / PHP
        r"Uncaught PDOException",
        r"mysql_fetch_",
        r"supplied argument is not a valid MySQL",
        # PostgreSQL
        r"org\.postgresql\.util\.PSQLException",
        # MySQL extractvalue
        r"XPATH syntax error",
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

_SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"]

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

# ── Form parsing ────────────────────────────────────────────────────────────
_FORM_RE     = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_ACTION_RE   = re.compile(r'\baction=["\']([^"\']*)["\']', re.IGNORECASE)
_METHOD_RE   = re.compile(r'\bmethod=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE    = re.compile(r'<input([^>]*)>', re.IGNORECASE)
_INAME_RE    = re.compile(r'\bname=["\']([^"\']*)["\']', re.IGNORECASE)
_IVALUE_RE   = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.IGNORECASE)
_ITYPE_RE    = re.compile(r'\btype=["\']([^"\']*)["\']', re.IGNORECASE)
_TEXTAREA_RE = re.compile(r'<textarea[^>]+name=["\']([^"\']*)["\']', re.IGNORECASE)

_INJECTABLE_TYPES = {"text", "search", "email", "number", "url", "tel", "password", "textarea", ""}


def _parse_forms(html: str, base_url: str) -> List[Dict]:
    forms = []
    for m in _FORM_RE.finditer(html):
        tag  = m.group(0)[:300]
        body = m.group(1)

        action_m = _ACTION_RE.search(tag)
        method_m = _METHOD_RE.search(tag)

        method     = (method_m.group(1) if method_m else "get").lower().strip()
        raw_action = action_m.group(1) if action_m else ""
        action     = urljoin(base_url, raw_action) if raw_action else base_url

        fields: Dict[str, Dict] = {}
        for inp in _INPUT_RE.finditer(body):
            attrs = inp.group(1)
            nm    = _INAME_RE.search(attrs)
            val   = _IVALUE_RE.search(attrs)
            tp    = _ITYPE_RE.search(attrs)
            if not nm:
                continue
            fields[nm.group(1)] = {
                "value": val.group(1) if val else "",
                "type":  (tp.group(1) if tp else "text").lower().strip(),
            }

        for ta in _TEXTAREA_RE.finditer(body):
            fields[ta.group(1)] = {"value": "", "type": "textarea"}

        forms.append({"action": action, "method": method, "fields": fields})
    return forms


class InjectionModule(BaseModule):
    NAME     = "injection"
    CATEGORY = "Injection"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if params:
            findings.extend(await self._scan_get_params(url, parsed, params))

        # POST form injection
        try:
            base_resp = await self._client.get(url)
            forms = _parse_forms(base_resp.text[:30000], url)
            for form in forms:
                if form["method"] in ("post", "put"):
                    findings.extend(await self._scan_post_form(url, form))
        except Exception:
            pass

        return self._dedup(findings)

    async def _scan_get_params(
        self, url: str, parsed, params: List
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for idx, (pname, pval) in enumerate(params):
            # ── SQL Injection (single-quote error-based) ────────────
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

            # ── Boolean-blind SQLi ──────────────────────────────────
            blind = await self._check_boolean_blind(url, parsed, params, idx, pname, pval)
            if blind:
                findings.append(blind)

            # ── NoSQL Injection ─────────────────────────────────────
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

            # ── SSTI ────────────────────────────────────────────────
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

            # ── Command Injection (error-based) ─────────────────────
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

        return findings

    async def _check_boolean_blind(
        self, url: str, parsed, params: List, idx: int, pname: str, pval: str
    ) -> Optional[Dict[str, Any]]:
        """Return a finding if AND 1=1 vs AND 1=2 show a meaningful response difference."""
        try:
            params_t = list(params); params_t[idx] = (pname, pval + " AND 1=1")
            params_f = list(params); params_f[idx] = (pname, pval + " AND 1=2")
            url_t = urlunparse(parsed._replace(query=urlencode(params_t)))
            url_f = urlunparse(parsed._replace(query=urlencode(params_f)))

            r_t = await self._client.get(url_t)
            r_f = await self._client.get(url_f)

            len_t = len(r_t.text)
            len_f = len(r_f.text)
            diff  = abs(len_t - len_f)

            if diff < 50:
                return None
            if diff / max(len_t, len_f, 1) < 0.05:
                return None

            # Confirm 1=1 response is close to baseline (so 1=2 is the outlier)
            r_b   = await self._client.get(url)
            len_b = len(r_b.text)
            if abs(len_t - len_b) > diff * 0.8:
                return None

            return self._finding(
                name="sql_injection_blind",
                severity="high",
                confidence="medium",
                description=f"SQL Injection (boolean-blind) potentielle — paramètre « {pname} »",
                url=url,
                location=url_t,
                evidence=f"AND 1=1 → {len_t} octets, AND 1=2 → {len_f} octets (diff={diff})",
                impact=(
                    "Un attaquant peut exfiltrer des données bit par bit via des requêtes "
                    "conditionnelles (blind SQLi). Accès possible à toute la base de données."
                ),
                recommendation=(
                    "Utiliser des requêtes paramétrées (prepared statements). "
                    "Valider et filtrer toutes les entrées utilisateur."
                ),
            )
        except Exception:
            return None

    async def _scan_post_form(self, url: str, form: Dict) -> List[Dict[str, Any]]:
        """Test SQLi, RCE, LFI and SSTI on each injectable POST form field."""
        findings: List[Dict[str, Any]] = []
        action = form["action"]
        fields = form["fields"]

        injectable = [
            name for name, meta in fields.items()
            if meta["type"] in _INJECTABLE_TYPES
        ]
        if not injectable:
            return findings

        base_data = {name: meta["value"] for name, meta in fields.items()}

        for fname in injectable:
            fval = fields[fname]["value"]

            # ── SQL Injection (single-quote error-based) ────────────
            post_data = dict(base_data)
            post_data[fname] = "'" + fval
            try:
                resp = await self._client.post(action, data=post_data)
                for pat in _SQL_ERROR_PATTERNS:
                    m = pat.search(resp.text[:8000])
                    if m:
                        findings.append(self._finding(
                            name="sql_injection_error_based",
                            severity="high",
                            confidence="confirmed",
                            description=f"SQL Injection (error-based, POST) — champ « {fname} »",
                            url=url,
                            location=action,
                            evidence=m.group(0)[:300],
                            impact=(
                                "Un attaquant peut extraire des données, contourner "
                                "l'authentification ou exécuter des commandes système."
                            ),
                            recommendation=(
                                "Utiliser des requêtes paramétrées (prepared statements). "
                                "Valider et filtrer toutes les entrées utilisateur."
                            ),
                        ))
                        break
            except Exception:
                pass

            # ── Command Injection / RCE (POST) ─────────────────────
            for cmd_suffix, label in [("; id", "semicolon"), ("| id", "pipe"), ("&& id", "AND")]:
                post_data = dict(base_data)
                post_data[fname] = fval + cmd_suffix
                try:
                    resp = await self._client.post(action, data=post_data)
                    for pat in _CMD_ERROR_PATTERNS:
                        m = pat.search(resp.text[:4000])
                        if m:
                            findings.append(self._finding(
                                name="command_injection_detected",
                                severity="critical",
                                confidence="high",
                                description=f"Command Injection possible (POST, {label}) — champ « {fname} »",
                                url=url,
                                location=action,
                                evidence=m.group(0)[:200],
                                impact=(
                                    "Exécution de commandes système arbitraires sur le serveur — "
                                    "compromission totale possible."
                                ),
                                recommendation=(
                                    "Ne jamais passer des entrées utilisateur à des fonctions "
                                    "d'exécution système. Utiliser des API spécialisées."
                                ),
                            ))
                            break
                except Exception:
                    pass

            # ── LFI / Path Traversal (POST) ────────────────────────
            _LFI_PROBE = re.compile(r'root:[x*!]:0:0:|for 16-bit app support', re.IGNORECASE)
            for lfi_payload, lfi_label in [
                ("../../../etc/passwd",       "3-level traversal"),
                ("../../../../etc/passwd",    "4-level traversal"),
                ("../../../windows/win.ini",  "Windows 3-level"),
            ]:
                post_data = dict(base_data)
                post_data[fname] = lfi_payload
                try:
                    resp = await self._client.post(action, data=post_data)
                    if _LFI_PROBE.search(resp.text[:5000]):
                        findings.append(self._finding(
                            name="lfi_path_traversal",
                            severity="critical",
                            confidence="confirmed",
                            description=f"LFI / Path Traversal (POST, {lfi_label}) — champ « {fname} »",
                            url=url,
                            location=action,
                            evidence=_LFI_PROBE.search(resp.text[:500]).group(0)[:100],
                            impact=(
                                "Lecture de fichiers arbitraires sur le serveur — "
                                "accès possible aux credentials, clés privées, configs."
                            ),
                            recommendation=(
                                "Valider et canonicaliser les chemins de fichiers. "
                                "Ne jamais utiliser des entrées utilisateur dans des chemins. "
                                "Utiliser une liste blanche de fichiers autorisés."
                            ),
                        ))
                        break
                except Exception:
                    pass

            # ── SSTI (POST) ────────────────────────────────────────
            for ssti_payload in _SSTI_PAYLOADS:
                post_data = dict(base_data)
                post_data[fname] = ssti_payload
                try:
                    resp = await self._client.post(action, data=post_data)
                    body = resp.text[:6000]
                    if "49" in body and ssti_payload not in body:
                        findings.append(self._finding(
                            name="ssti_detected",
                            severity="critical",
                            confidence="high",
                            description=f"SSTI (POST) — champ « {fname} » avec {ssti_payload!r}",
                            url=url,
                            location=action,
                            evidence=f"Payload {ssti_payload!r} → résultat '49' dans la réponse POST",
                            impact=(
                                "SSTI peut permettre l'exécution de code arbitraire (RCE) "
                                "sur le serveur, lecture de fichiers et pivoting."
                            ),
                            recommendation=(
                                "Ne jamais interpoler des entrées utilisateur dans des templates. "
                                "Utiliser un moteur de template sécurisé avec sandbox."
                            ),
                        ))
                        break
                except Exception:
                    pass

        return findings
