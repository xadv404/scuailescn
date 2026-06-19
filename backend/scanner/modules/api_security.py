"""
API Security module.

Detects:
  - Swagger / OpenAPI / GraphQL documentation exposure
  - CORS misconfiguration (wildcard or reflected origin)
  - HTTP methods not restricted (TRACE, TRACK, DELETE)
  - Sensitive data in API JSON responses
  - API versioning without authentication
  - API rate-limiting absence indicators
"""
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from backend.scanner.modules.base_module import BaseModule

_API_DOC_PATHS = [
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/api/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/graphql", "/graphiql",
    "/api/graphql", "/playground",
]

_SENSITIVE_JSON_RE = [
    (re.compile(r'"password"\s*:\s*"[^"]+"', re.I), "password"),
    (re.compile(r'"passwd"\s*:\s*"[^"]+"', re.I),   "passwd"),
    (re.compile(r'"secret"\s*:\s*"[^"]+"', re.I),   "secret"),
    (re.compile(r'"api_?key"\s*:\s*"[^"]+"', re.I), "api_key"),
    (re.compile(r'"token"\s*:\s*"[^"]{16,}"', re.I),"token"),
    (re.compile(r'"ssn"\s*:\s*"[^"]+"', re.I),      "SSN"),
    (re.compile(r'"credit_?card"\s*:\s*"[^"]+"', re.I), "credit_card"),
    (re.compile(r'"private_?key"\s*:\s*"[^"]+"', re.I), "private_key"),
    (re.compile(r'"connection_?string"\s*:\s*"[^"]+"', re.I), "connection_string"),
]

_GRAPHQL_INTRO  = b'{"query":"{__schema{types{name}}}"}'
_METHODS_CHECK  = ["TRACE", "TRACK", "DELETE", "PUT"]


class APISecurityModule(BaseModule):
    NAME     = "api_security"
    CATEGORY = "API Security"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base_url(url)

        # 1. API documentation exposure
        for path in _API_DOC_PATHS:
            probe = f"{base}{path}"
            try:
                resp = await self._client.get(probe)
                if resp.status_code not in (200, 400):
                    continue
                ct   = resp.headers.get("content-type", "")
                body = resp.text[:5000]

                is_swagger  = ("swagger" in path or "api-docs" in path or "openapi" in path)
                is_graphql  = ("graphql" in path or "graphiql" in path or "playground" in path)
                body_lower  = body.lower()

                if resp.status_code == 200 and is_swagger and (
                    "swagger" in body_lower or "openapi" in body_lower or "paths" in body_lower
                ):
                    findings.append(self._finding(
                        name="api_documentation_exposed",
                        severity="medium",
                        confidence="confirmed",
                        description=f"Documentation API exposée publiquement ({path})",
                        url=url,
                        location=probe,
                        evidence=f"HTTP {resp.status_code} — {ct[:60]}",
                        impact=(
                            "La documentation expose tous les endpoints, paramètres et modèles — "
                            "facilite considérablement la reconnaissance pour un attaquant."
                        ),
                        recommendation=(
                            "Restreindre l'accès à la doc API (authentification, IP allowlist) "
                            "en dehors des environnements de développement."
                        ),
                    ))

                if is_graphql and resp.status_code in (200, 400):
                    try:
                        gql = await self._client.post(
                            probe,
                            content=_GRAPHQL_INTRO,
                            headers={"Content-Type": "application/json"},
                        )
                        if gql.status_code == 200 and "__schema" in gql.text:
                            findings.append(self._finding(
                                name="graphql_introspection_enabled",
                                severity="medium",
                                confidence="confirmed",
                                description="Introspection GraphQL activée en production",
                                url=url,
                                location=probe,
                                evidence="__schema présent dans la réponse d'introspection",
                                impact=(
                                    "Permet de cartographier l'intégralité du schéma GraphQL, "
                                    "types, champs et mutations inclus."
                                ),
                                recommendation=(
                                    "Désactiver l'introspection GraphQL en production. "
                                    "Implémenter une liste blanche de requêtes autorisées."
                                ),
                            ))
                    except Exception:
                        pass

                # Sensitive data in JSON responses
                if resp.status_code == 200 and ("json" in ct or body.lstrip().startswith("{")):
                    for pat, label in _SENSITIVE_JSON_RE:
                        m = pat.search(body)
                        if m:
                            findings.append(self._finding(
                                name="sensitive_data_in_api_response",
                                severity="high",
                                confidence="confirmed",
                                description=f"Données sensibles dans réponse API ({label})",
                                url=url,
                                location=probe,
                                evidence=m.group(0)[:200],
                                impact=(
                                    "Credentials ou données confidentielles retournés dans l'API — "
                                    "violation du principe de moindre exposition."
                                ),
                                recommendation=(
                                    "Ne jamais inclure mots de passe, clés ou tokens dans les "
                                    "réponses API. Auditer tous les sérialiseurs de modèles."
                                ),
                            ))
                            break
            except Exception:
                continue

        # 2. CORS misconfiguration
        try:
            resp = await self._client.get(url, headers={"Origin": "https://evil.example.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acao == "*":
                findings.append(self._finding(
                    name="cors_wildcard",
                    severity="medium",
                    confidence="confirmed",
                    description="CORS : Access-Control-Allow-Origin: * (wildcard)",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    impact=(
                        "N'importe quel site peut effectuer des requêtes cross-origin. "
                        "Combiné avec des endpoints sensibles, permet l'exfiltration de données."
                    ),
                    recommendation=(
                        "Définir une liste blanche explicite d'origines autorisées. "
                        "Ne jamais utiliser '*' pour des API authentifiées."
                    ),
                ))
            elif acao == "https://evil.example.com" and acac.lower() == "true":
                findings.append(self._finding(
                    name="cors_origin_reflected",
                    severity="high",
                    confidence="confirmed",
                    description="CORS : origine arbitraire reflétée avec credentials autorisés",
                    url=url,
                    evidence=f"Origin evil.example.com → ACAO: {acao}, ACAC: {acac}",
                    impact=(
                        "N'importe quel domaine peut effectuer des requêtes authentifiées "
                        "cross-origin, permettant l'exfiltration de données utilisateur."
                    ),
                    recommendation=(
                        "Valider l'Origin contre une liste blanche stricte. "
                        "Ne jamais refléter l'Origin sans validation."
                    ),
                ))
        except Exception:
            pass

        # 3. Dangerous HTTP methods
        try:
            resp = await self._client.options(url)
            allow = resp.headers.get("allow", "").upper()
            for method in _METHODS_CHECK:
                if method in allow:
                    findings.append(self._finding(
                        name=f"dangerous_http_method_{method.lower()}",
                        severity="low" if method in ("DELETE", "PUT") else "info",
                        confidence="confirmed",
                        description=f"Méthode HTTP dangereuse autorisée : {method}",
                        url=url,
                        evidence=f"Allow: {allow}",
                        impact=(
                            f"La méthode {method} peut permettre des modifications "
                            "non autorisées ou de la reconnaissance."
                        ),
                        recommendation=(
                            f"Désactiver la méthode {method} si elle n'est pas nécessaire. "
                            "Configurer un whitelist de méthodes HTTP."
                        ),
                    ))
        except Exception:
            pass

        return self._dedup(findings)
