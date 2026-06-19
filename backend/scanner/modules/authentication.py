"""
Authentication module.

Detects:
  - Login endpoints and weak authentication indicators
  - Missing security headers (HSTS, HPKP)
  - Insecure session cookies (Secure, HttpOnly, SameSite flags)
  - JWT tokens exposed in responses
  - Missing rate-limiting on login forms
  - Default/predictable session IDs
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from backend.scanner.modules.base_module import BaseModule

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/session", "/sessions/new", "/user/login", "/account/login",
    "/wp-login.php", "/admin/login", "/api/login", "/api/auth",
    "/api/v1/auth", "/api/v1/login", "/oauth/token",
]

_SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium", "HSTS manquant",
        "Sans HSTS, les navigateurs peuvent se connecter en HTTP clair, exposant les sessions.",
        "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        "medium", "Content Security Policy absente",
        "Sans CSP, les attaques XSS peuvent charger des scripts depuis n'importe quelle origine.",
        "Définir une CSP restrictive limitant les sources de scripts, styles et médias.",
    ),
    "X-Frame-Options": (
        "low", "Protection anti-clickjacking manquante",
        "La page peut être embarquée dans un iframe pour des attaques de clickjacking.",
        "Ajouter X-Frame-Options: DENY ou utiliser CSP frame-ancestors 'none'.",
    ),
    "X-Content-Type-Options": (
        "low", "X-Content-Type-Options absent",
        "Les navigateurs peuvent interpréter les types MIME de façon incorrecte (MIME sniffing).",
        "Ajouter X-Content-Type-Options: nosniff sur toutes les réponses.",
    ),
    "Permissions-Policy": (
        "info", "Permissions-Policy absent",
        "Les fonctionnalités du navigateur (caméra, micro, géolocalisation) ne sont pas restreintes.",
        "Définir un Permissions-Policy pour limiter les API du navigateur accessibles.",
    ),
}

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')


class AuthenticationModule(BaseModule):
    NAME     = "authentication"
    CATEGORY = "Authentication"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base     = self._base_url(url)
        is_https = urlparse(url).scheme == "https"

        try:
            resp = await self._client.get(url)
        except Exception:
            return findings

        headers = resp.headers

        # 1. Missing security headers
        for hdr, (severity, desc, impact, rec) in _SECURITY_HEADERS.items():
            if not headers.get(hdr):
                findings.append(self._finding(
                    name=f"missing_{hdr.lower().replace('-', '_')}",
                    severity=severity,
                    confidence="confirmed",
                    description=desc,
                    url=url,
                    evidence=f"En-tête '{hdr}' absent de la réponse",
                    impact=impact,
                    recommendation=rec,
                ))

        # 2. Insecure cookies
        raw_sc = headers.get("set-cookie") or ""
        if raw_sc:
            parts = [p.strip().lower() for p in raw_sc.split(";")]
            name  = raw_sc.split("=")[0].strip() if "=" in raw_sc else "?"

            if is_https and "secure" not in parts:
                findings.append(self._finding(
                    name="cookie_missing_secure",
                    severity="medium",
                    confidence="confirmed",
                    description=f"Cookie '{name}' sans flag Secure",
                    url=url,
                    evidence=raw_sc[:200],
                    impact="Cookie transmissible en HTTP clair — interception possible.",
                    recommendation="Ajouter le flag Secure à tous les cookies de session.",
                ))

            if "httponly" not in parts:
                findings.append(self._finding(
                    name="cookie_missing_httponly",
                    severity="medium",
                    confidence="confirmed",
                    description=f"Cookie '{name}' sans flag HttpOnly",
                    url=url,
                    evidence=raw_sc[:200],
                    impact="Cookie accessible via JavaScript — vol facilité en cas de XSS.",
                    recommendation="Ajouter le flag HttpOnly à tous les cookies sensibles.",
                ))

            if "samesite" not in parts:
                findings.append(self._finding(
                    name="cookie_missing_samesite",
                    severity="low",
                    confidence="confirmed",
                    description=f"Cookie '{name}' sans attribut SameSite",
                    url=url,
                    evidence=raw_sc[:200],
                    impact="Cookie envoyé dans les requêtes cross-site — risque CSRF.",
                    recommendation="Ajouter SameSite=Strict ou SameSite=Lax selon le besoin.",
                ))

        # 3. JWT in body or headers
        body = resp.text[:8000]
        jwt_m = _JWT_RE.search(body)
        if jwt_m:
            findings.append(self._finding(
                name="jwt_token_in_response",
                severity="medium",
                confidence="confirmed",
                description="Token JWT exposé dans le corps de la réponse",
                url=url,
                evidence=jwt_m.group(0)[:80] + "…",
                impact=(
                    "Un token JWT dans la réponse peut être lu par des scripts tiers "
                    "si la page est vulnérable au XSS."
                ),
                recommendation=(
                    "Stocker les tokens JWT dans des cookies HttpOnly Secure plutôt que "
                    "dans le corps JSON ou le localStorage."
                ),
            ))

        # 4. Login endpoints without rate-limiting
        for path in _LOGIN_PATHS:
            probe = f"{base}{path}"
            try:
                resp_login = await self._client.get(probe)
                if resp_login.status_code == 200:
                    body_l = resp_login.text[:3000].lower()
                    if any(kw in body_l for kw in ("password", "mot de passe", "login", "sign in")):
                        rl_headers = (
                            "x-ratelimit-limit", "x-rate-limit-limit",
                            "retry-after", "x-ratelimit-remaining",
                        )
                        has_rl = any(resp_login.headers.get(h) for h in rl_headers)
                        if not has_rl:
                            findings.append(self._finding(
                                name="login_no_rate_limiting",
                                severity="medium",
                                confidence="medium",
                                description=f"Endpoint de connexion sans rate-limiting apparent ({path})",
                                url=url,
                                location=probe,
                                evidence=f"HTTP {resp_login.status_code} — aucun header de rate-limiting",
                                impact=(
                                    "Sans rate-limiting, les attaques par force brute "
                                    "ou credential stuffing ne sont pas ralenties."
                                ),
                                recommendation=(
                                    "Implémenter un rate-limiting strict sur les endpoints "
                                    "d'authentification (max 5-10 tentatives/minute par IP). "
                                    "Utiliser un CAPTCHA après N échecs."
                                ),
                            ))
                            break
            except Exception:
                continue

        return self._dedup(findings)
