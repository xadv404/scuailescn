"""
API Security module.

Probes common API paths for:
  - Exposed Swagger / OpenAPI documentation
  - GraphQL introspection
  - Sensitive data in JSON API responses
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from backend.scanner.modules.base_module import BaseModule

_API_PROBE_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/graphql",
    "/api/debug",
    "/api/admin",
    "/api/internal",
]

_SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]+"', re.IGNORECASE),          "password"),
    (re.compile(r'"secret"\s*:\s*"[^"]+"', re.IGNORECASE),            "secret"),
    (re.compile(r'"api_key"\s*:\s*"[^"]+"', re.IGNORECASE),           "api_key"),
    (re.compile(r'"token"\s*:\s*"[^"]{16,}"', re.IGNORECASE),         "token"),
    (re.compile(r'"connection_string"\s*:\s*"[^"]+"', re.IGNORECASE), "connection_string"),
]

_GRAPHQL_INTRO = '{"query":"{__schema{types{name}}}"}'


class APIRisksModule(BaseModule):
    NAME     = "api_risks"
    CATEGORY = "API Security"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base(url)

        for path in _API_PROBE_PATHS:
            probe = urljoin(base, path)
            try:
                resp = await self._client.get(probe)
            except Exception:
                continue

            if resp.status_code not in (200, 400, 401, 403):
                continue

            body = resp.text[:6000]
            ct   = resp.headers.get("content-type", "")

            # Swagger / OpenAPI doc
            if resp.status_code == 200 and (
                "swagger" in path or "openapi" in path
                or ("swagger" in body.lower() and "json" in ct)
            ):
                findings.append(self._finding(
                    type="api_doc_exposed",
                    severity="medium",
                    confidence="confirmed",
                    description=f"Documentation API exposée publiquement ({path})",
                    url=url,
                    location=probe,
                    evidence=f"HTTP {resp.status_code} — {ct[:80]}",
                    impact=(
                        "La documentation expose tous les endpoints, paramètres et modèles, "
                        "facilitant considérablement la reconnaissance pour un attaquant."
                    ),
                    recommendation=(
                        "Restreindre l'accès à la documentation API (authentification, "
                        "IP allowlist) en dehors des environnements de développement."
                    ),
                ))

            # GraphQL introspection
            if resp.status_code in (200, 400) and "graphql" in path:
                try:
                    gql = await self._client.post(
                        probe,
                        content=_GRAPHQL_INTRO,
                        headers={"Content-Type": "application/json"},
                    )
                    if gql.status_code == 200 and "__schema" in gql.text:
                        findings.append(self._finding(
                            type="graphql_introspection_enabled",
                            severity="medium",
                            confidence="confirmed",
                            description="Introspection GraphQL activée en production",
                            url=url,
                            location=probe,
                            evidence="__schema trouvé dans la réponse d'introspection",
                            impact=(
                                "L'introspection permet à un attaquant de cartographier "
                                "l'intégralité du schéma GraphQL, types et champs inclus."
                            ),
                            recommendation=(
                                "Désactiver l'introspection GraphQL en production. "
                                "Implémenter une liste blanche de requêtes autorisées."
                            ),
                        ))
                except Exception:
                    pass

            # Sensitive data in JSON responses
            if resp.status_code == 200 and "json" in ct:
                for pat, label in _SENSITIVE_PATTERNS:
                    m = pat.search(body)
                    if m:
                        findings.append(self._finding(
                            type="sensitive_data_in_api",
                            severity="high",
                            confidence="confirmed",
                            description=f"Donnée sensible exposée dans une réponse API ({label})",
                            url=url,
                            location=probe,
                            evidence=m.group(0)[:200],
                            impact=(
                                "Des credentials ou données confidentielles sont retournés "
                                "dans les réponses API, violant le principe de moindre exposition."
                            ),
                            recommendation=(
                                "Ne jamais retourner mots de passe, clés ou tokens dans les "
                                "réponses API. Auditer tous les sérialiseurs/modèles de données."
                            ),
                        ))
                        break

        return self._dedup(findings)

    @staticmethod
    def _base(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    @staticmethod
    def _dedup(findings: List[Dict]) -> List[Dict]:
        seen: set = set()
        out = []
        for f in findings:
            if f["type"] not in seen:
                seen.add(f["type"])
                out.append(f)
        return out
