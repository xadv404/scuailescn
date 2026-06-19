"""
SQLi Pre-Filter — détecteur rapide (2-8 s par URL).

Objective : trier les URLs AVANT SQLMap pour ne lancer le dump que sur
des cibles prometteuses et ignorer les URLs sans vecteur d'injection.

Signaux détectés :
  HIGH   — réponse SQL error après injection de '  →  candidat certain
  MEDIUM — URL avec paramètres GET ou formulaires  →  candidat probable
  LOW    — page statique sans vecteur d'injection  →  skip SQLMap

Retourne :
  {
    "candidate": bool,
    "confidence": "high" | "medium" | "none",
    "reasons":   [str, ...],
    "params":    [str, ...],   # paramètres détectés
    "has_forms": bool,
  }
"""
import asyncio
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

# ── Patterns d'erreur SQL ──────────────────────────────────────
_SQL_ERRORS = [re.compile(p, re.IGNORECASE) for p in [
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
    r"Uncaught PDOException",
    r"org\.postgresql\.util\.PSQLException",
    r"supplied argument is not a valid MySQL",
    r"mysql_fetch",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
]]

# ── Patterns de formulaires HTML ───────────────────────────────
_FORM_INPUT_RE = re.compile(
    r'<input[^>]+type=["\']?(?:text|search|hidden|number|email)["\']?',
    re.IGNORECASE,
)
_FORM_RE = re.compile(r'<form\b', re.IGNORECASE)

# ── Noms de paramètres classiquement injectables ───────────────
_INJECTABLE_PARAM_NAMES = {
    "id", "cat", "page", "article", "product", "item", "news", "ref",
    "user", "action", "p", "pid", "cid", "nid", "sid", "fid", "tid",
    "view", "q", "query", "search", "keyword", "order", "sort",
    "limit", "offset", "lang", "type", "mode", "section", "chapter",
    "doc", "file", "path", "dir", "url", "link", "next", "prev",
}

_INJECT_PAYLOAD = "'"


async def sqli_prefilter(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Pré-filtre rapide — renvoie un dict avec candidate/confidence/reasons.
    """
    reasons: List[str] = []
    params_found: List[str] = []
    has_forms = False

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"},
        ) as client:
            parsed  = urlparse(url)
            qparams = parse_qsl(parsed.query, keep_blank_values=True)

            # ── 1. Réponse de base ─────────────────────────────
            try:
                base_resp = await client.get(url)
                body_base = base_resp.text[:10_000]

                # SQL error dans la réponse initiale → HAUTE confiance
                for pat in _SQL_ERRORS:
                    m = pat.search(body_base)
                    if m:
                        reasons.append(f"SQL error dans la réponse de base : {m.group(0)[:80]}")
                        return _result(True, "high", reasons, params_found, has_forms)

                # Formulaire avec champs texte → MOYEN
                if _FORM_RE.search(body_base) and _FORM_INPUT_RE.search(body_base):
                    has_forms = True
                    reasons.append("Formulaire avec champs de saisie détecté")

            except Exception:
                pass

            # ── 2. Params GET connus ───────────────────────────
            for name, _ in qparams:
                params_found.append(name)
                if name.lower() in _INJECTABLE_PARAM_NAMES:
                    reasons.append(f"Paramètre injectable connu : {name}")

            # ── 3. Probe ' sur chaque param ────────────────────
            probe_tasks = []
            for idx, (name, val) in enumerate(qparams):
                probe = list(qparams)
                probe[idx] = (name, _INJECT_PAYLOAD + val)
                probe_url = urlunparse(parsed._replace(query=urlencode(probe)))
                probe_tasks.append(_probe_param(client, name, probe_url))

            if probe_tasks:
                results = await asyncio.gather(*probe_tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, dict) and res.get("sqli"):
                        reasons.append(res["reason"])
                        return _result(True, "high", reasons, params_found, has_forms)

    except Exception:
        pass

    # ── Décision finale ────────────────────────────────────────
    if params_found or has_forms:
        return _result(True, "medium", reasons or ["Paramètres/formulaires présents"], params_found, has_forms)

    return _result(False, "none", ["Aucun vecteur d'injection détecté"], params_found, has_forms)


async def _probe_param(client: httpx.AsyncClient, name: str, probe_url: str) -> Dict:
    try:
        resp = await client.get(probe_url)
        body = resp.text[:8_000]
        for pat in _SQL_ERRORS:
            m = pat.search(body)
            if m:
                return {
                    "sqli": True,
                    "reason": f"SQL error sur param '{name}' : {m.group(0)[:80]}",
                }
    except Exception:
        pass
    return {"sqli": False, "reason": ""}


def _result(
    candidate: bool,
    confidence: str,
    reasons: List[str],
    params: List[str],
    has_forms: bool,
) -> Dict[str, Any]:
    return {
        "candidate":  candidate,
        "confidence": confidence,
        "reasons":    reasons,
        "params":     params,
        "has_forms":  has_forms,
    }
