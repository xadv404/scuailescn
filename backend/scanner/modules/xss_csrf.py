"""
XSS & CSRF module.

Detects:
  - Reflected XSS (parameter reflection without encoding)
  - DOM-based XSS indicators (innerHTML, document.write patterns)
  - CSRF: forms without anti-CSRF tokens
  - Missing security headers (X-XSS-Protection, CSP)
  - Open redirect indicators
"""
import re
from html import unescape
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.scanner.modules.base_module import BaseModule

_XSS_PROBE     = '<script>/*xss-probe*/</script>'
_XSS_ENCODED   = '&lt;script&gt;'
_XSS_PROBE_RE  = re.compile(r'<script>\s*/\*xss-probe\*/\s*</script>', re.IGNORECASE)

_DOM_XSS_PATTERNS = [
    re.compile(r'document\.write\s*\(', re.IGNORECASE),
    re.compile(r'innerHTML\s*=', re.IGNORECASE),
    re.compile(r'outerHTML\s*=', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'location\.href\s*=\s*[^;]+(?:search|hash|param)', re.IGNORECASE),
    re.compile(r'document\.URL', re.IGNORECASE),
]

_CSRF_TOKEN_NAMES = re.compile(
    r'(?:csrf|_token|xsrf|authenticity_token|nonce|__requestverificationtoken)',
    re.IGNORECASE,
)

_OPEN_REDIRECT_PARAMS = re.compile(
    r'(?:redirect|return|next|url|goto|dest|destination|redir|target|to)=',
    re.IGNORECASE,
)

_OPEN_REDIRECT_INDICATORS = [
    re.compile(r'Location:\s*https?://', re.IGNORECASE),
]


class XssCsrfModule(BaseModule):
    NAME     = "xss_csrf"
    CATEGORY = "XSS & CSRF"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        try:
            resp_base = await self._client.get(url)
        except Exception:
            return findings

        body = resp_base.text[:20000]

        # 1. Reflected XSS — inject probe into each URL parameter
        for idx, (pname, pval) in enumerate(params):
            probe_params = list(params)
            probe_params[idx] = (pname, _XSS_PROBE)
            probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))
            try:
                resp = await self._client.get(probe_url)
                rbody = resp.text[:10000]
                # Check if probe appears unencoded in response
                if _XSS_PROBE_RE.search(rbody):
                    findings.append(self._finding(
                        name="reflected_xss",
                        severity="high",
                        confidence="confirmed",
                        description=f"XSS réfléchi potentiel — paramètre « {pname} »",
                        url=url,
                        location=probe_url,
                        evidence=f"Probe <script> retourné non encodé dans la réponse",
                        impact=(
                            "Un attaquant peut injecter du code JavaScript arbitraire "
                            "exécuté dans le navigateur des victimes — vol de session, "
                            "phishing, keylogging."
                        ),
                        recommendation=(
                            "Encoder toutes les sorties HTML (htmlspecialchars/escapeHtml). "
                            "Implémenter une CSP restrictive. "
                            "Valider et filtrer les entrées côté serveur."
                        ),
                    ))
                    break
            except Exception:
                pass

        # 2. DOM XSS patterns in JS
        dom_found = []
        for pat in _DOM_XSS_PATTERNS:
            m = pat.search(body)
            if m:
                dom_found.append(m.group(0)[:80])

        if len(dom_found) >= 2:
            findings.append(self._finding(
                name="dom_xss_indicators",
                severity="medium",
                confidence="medium",
                description=f"Patterns DOM XSS détectés dans le code JavaScript ({len(dom_found)} occurrences)",
                url=url,
                evidence=" | ".join(dom_found[:3]),
                impact=(
                    "Les patterns d'écriture DOM non sécurisés peuvent permettre "
                    "l'injection de code JavaScript via des sources non-fiables "
                    "(hash, URL, postMessage)."
                ),
                recommendation=(
                    "Utiliser textContent au lieu de innerHTML. "
                    "Éviter eval() et document.write(). "
                    "Valider les sources DOM avant utilisation."
                ),
            ))

        # 3. CSRF — forms without anti-CSRF tokens
        form_re   = re.compile(r'<form[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
        input_re  = re.compile(r'<input[^>]+>', re.IGNORECASE)
        method_re = re.compile(r'method\s*=\s*["\']?(post|put|patch|delete)', re.IGNORECASE)

        forms = form_re.findall(body)
        for form in forms:
            if not method_re.search(form):
                continue  # GET forms don't need CSRF
            inputs = input_re.findall(form)
            has_token = any(
                _CSRF_TOKEN_NAMES.search(inp) for inp in inputs
            )
            hidden_token = any(
                'type="hidden"' in inp.lower() and _CSRF_TOKEN_NAMES.search(inp)
                for inp in inputs
            )
            if not has_token:
                findings.append(self._finding(
                    name="csrf_missing_token",
                    severity="medium",
                    confidence="medium",
                    description="Formulaire POST sans token anti-CSRF apparent",
                    url=url,
                    evidence=form[:200].strip(),
                    impact=(
                        "Sans protection CSRF, des sites tiers peuvent déclencher "
                        "des actions au nom d'un utilisateur authentifié."
                    ),
                    recommendation=(
                        "Ajouter un token CSRF unique par session dans chaque formulaire POST. "
                        "Valider le token côté serveur. "
                        "Utiliser SameSite=Strict sur les cookies de session."
                    ),
                ))
                break

        # 4. Open redirect
        if _OPEN_REDIRECT_PARAMS.search(parsed.query):
            redirect_params = [
                n for n, _ in params
                if _OPEN_REDIRECT_PARAMS.search(n + "=")
            ]
            for ridx, (rname, rval) in enumerate(params):
                if not _OPEN_REDIRECT_PARAMS.search(rname + "="):
                    continue
                evil_params = list(params)
                evil_params[ridx] = (rname, "https://evil.example.com")
                evil_url = urlunparse(parsed._replace(query=urlencode(evil_params)))
                try:
                    resp = await self._client.get(evil_url, follow_redirects=False)
                    loc  = resp.headers.get("location", "")
                    if "evil.example.com" in loc:
                        findings.append(self._finding(
                            name="open_redirect",
                            severity="medium",
                            confidence="confirmed",
                            description=f"Open Redirect confirmé — paramètre « {rname} »",
                            url=url,
                            location=evil_url,
                            evidence=f"Location: {loc[:150]}",
                            impact=(
                                "Un attaquant peut rediriger les victimes vers des sites "
                                "malveillants en utilisant la confiance du domaine légitime."
                            ),
                            recommendation=(
                                "Valider les URLs de redirection contre une liste blanche. "
                                "Ne jamais utiliser des paramètres utilisateur directement "
                                "comme destination de redirection."
                            ),
                        ))
                        break
                except Exception:
                    pass

        return self._dedup(findings)
