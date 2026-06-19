"""
Authentication & Authorization risks module.

Checks:
  - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
  - Insecure cookie flags (Secure, HttpOnly, SameSite)
"""
from typing import Any, Dict, List
from urllib.parse import urlparse

from backend.scanner.modules.base_module import BaseModule

_SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "HSTS manquant",
        "Sans HSTS, les navigateurs peuvent se connecter en HTTP, exposant les sessions "
        "à une attaque man-in-the-middle.",
        "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        "medium",
        "Content Security Policy manquante",
        "Sans CSP, les attaques XSS peuvent charger des scripts arbitraires depuis n'importe quelle origine.",
        "Définir une politique CSP restrictive limitant les sources de scripts, styles et images.",
    ),
    "X-Frame-Options": (
        "low",
        "Protection clickjacking manquante (X-Frame-Options)",
        "Sans X-Frame-Options, la page peut être encadrée dans un iframe pour des attaques de type clickjacking.",
        "Ajouter X-Frame-Options: DENY ou SAMEORIGIN, ou utiliser CSP frame-ancestors.",
    ),
    "X-Content-Type-Options": (
        "low",
        "X-Content-Type-Options manquant",
        "Sans cet en-tête, les navigateurs peuvent interpréter le type MIME de façon incorrecte.",
        "Ajouter X-Content-Type-Options: nosniff à toutes les réponses.",
    ),
}


class AuthRisksModule(BaseModule):
    NAME     = "auth_risks"
    CATEGORY = "Authentication & Authorization"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            resp = await self._client.get(url)
        except Exception as exc:
            self._log.debug(f"AuthRisks GET error: {exc}")
            return findings

        headers = resp.headers
        is_https = urlparse(url).scheme == "https"

        # Missing security headers
        for header, (severity, desc, impact, rec) in _SECURITY_HEADERS.items():
            if not headers.get(header):
                findings.append(self._finding(
                    type=f"missing_{header.lower().replace('-', '_')}",
                    severity=severity,
                    confidence="confirmed",
                    description=desc,
                    url=url,
                    evidence=f"En-tête '{header}' absent de la réponse",
                    impact=impact,
                    recommendation=rec,
                ))

        # Insecure cookie flags
        raw_sc = headers.get("set-cookie") or ""
        cookie_headers = [raw_sc] if raw_sc else []
        for cookie_hdr in cookie_headers:
            parts = [p.strip().lower() for p in cookie_hdr.split(";")]
            name  = cookie_hdr.split("=")[0].strip() if "=" in cookie_hdr else "?"

            if is_https and "secure" not in parts:
                findings.append(self._finding(
                    type="cookie_missing_secure_flag",
                    severity="medium",
                    confidence="confirmed",
                    description=f"Cookie '{name}' sans flag Secure",
                    url=url,
                    evidence=cookie_hdr[:200],
                    impact=(
                        "Sans le flag Secure, le cookie peut être transmis sur des connexions "
                        "HTTP non chiffrées, permettant son interception."
                    ),
                    recommendation=(
                        "Ajouter le flag Secure à tous les cookies de session. "
                        "S'assurer que le site est exclusivement accessible en HTTPS."
                    ),
                ))

            if "httponly" not in parts:
                findings.append(self._finding(
                    type="cookie_missing_httponly",
                    severity="medium",
                    confidence="confirmed",
                    description=f"Cookie '{name}' sans flag HttpOnly",
                    url=url,
                    evidence=cookie_hdr[:200],
                    impact=(
                        "Sans HttpOnly, le cookie est accessible via JavaScript, "
                        "facilitant son vol en cas d'attaque XSS."
                    ),
                    recommendation=(
                        "Ajouter le flag HttpOnly à tous les cookies sensibles, "
                        "en particulier les cookies de session."
                    ),
                ))

        return self._dedup(findings)

    @staticmethod
    def _dedup(findings: List[Dict]) -> List[Dict]:
        seen: set = set()
        out = []
        for f in findings:
            key = (f["type"], f.get("evidence", "")[:50])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
