"""
Access Control module.

Detects:
  - Admin paths accessible without authentication
  - IDOR (Insecure Direct Object Reference) via ID enumeration
  - BOLA (Broken Object Level Authorization) on API endpoints
  - Broken Access Control on sensitive resources
"""
import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from backend.scanner.modules.base_module import BaseModule

_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/dashboard", "/console",
    "/manage", "/management", "/backend", "/backoffice",
    "/cpanel", "/controlpanel", "/panel", "/staff",
    "/superuser", "/root", "/sysadmin",
    "/api/admin", "/api/v1/admin", "/api/management",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/accounts", "/api/orders", "/api/internal",
    "/api/config", "/api/settings",
]

_SENSITIVE_PATHS = [
    "/users", "/accounts", "/orders", "/payments",
    "/invoices", "/reports", "/analytics", "/logs",
    "/config", "/settings", "/system", "/health",
    "/metrics", "/debug", "/status",
]

_ID_RE = re.compile(r"/(\d+)(?:/|$|\?)")


class AccessControlModule(BaseModule):
    NAME     = "access_control"
    CATEGORY = "Access Control"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base_url(url)

        # 1. Admin/privileged paths without auth
        for path in _ADMIN_PATHS:
            probe = f"{base}{path}"
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200 and len(resp.text) > 200:
                    body_lower = resp.text[:2000].lower()
                    # Check the response actually contains content (not a redirect page)
                    is_login = any(kw in body_lower for kw in (
                        "login", "sign in", "password", "username", "s'identifier"
                    ))
                    if not is_login:
                        findings.append(self._finding(
                            name="admin_path_accessible",
                            severity="high",
                            confidence="medium",
                            description=f"Chemin d'administration accessible sans authentification ({path})",
                            url=url,
                            location=probe,
                            evidence=f"HTTP {resp.status_code} — {len(resp.text)} octets sans redirection auth",
                            impact=(
                                "Fonctions d'administration accessibles sans authentification — "
                                "permet la modification de la configuration ou des données."
                            ),
                            recommendation=(
                                "Protéger toutes les routes d'administration par authentification forte. "
                                "Appliquer le principe de moindre privilège."
                            ),
                        ))
            except Exception:
                continue

        # 2. IDOR — numeric ID in the URL
        parsed    = urlparse(url)
        id_match  = _ID_RE.search(parsed.path)
        if id_match:
            current_id = int(id_match.group(1))
            for delta in (-1, 1, 2):
                alt_id    = current_id + delta
                alt_path  = parsed.path.replace(f"/{current_id}", f"/{alt_id}", 1)
                alt_url   = parsed._replace(path=alt_path).geturl()
                try:
                    resp_orig = await self._client.get(url)
                    resp_alt  = await self._client.get(alt_url)
                    if (resp_orig.status_code == 200
                            and resp_alt.status_code == 200
                            and len(resp_alt.text) > 100
                            and resp_orig.text[:200] != resp_alt.text[:200]):
                        findings.append(self._finding(
                            name="potential_idor",
                            severity="high",
                            confidence="medium",
                            description=f"Potentiel IDOR — ressource ID {alt_id} accessible sans contrôle apparent",
                            url=url,
                            location=alt_url,
                            evidence=f"ID {current_id} → ID {alt_id} : HTTP 200 ({len(resp_alt.text)} octets)",
                            impact=(
                                "Un attaquant peut accéder aux ressources d'autres utilisateurs "
                                "en incrémentant/décrémentant les identifiants numériques."
                            ),
                            recommendation=(
                                "Vérifier les autorisations côté serveur pour chaque ressource accédée. "
                                "Utiliser des UUID non prédictibles au lieu d'entiers séquentiels. "
                                "Implémenter des contrôles d'accès par propriétaire (ownership checks)."
                            ),
                        ))
                        break
                except Exception:
                    pass

        # 3. API BOLA — try common resource ID patterns
        for path in _SENSITIVE_PATHS:
            for rid in ("1", "2", "me", "0"):
                probe = f"{base}{path}/{rid}"
                try:
                    resp = await self._client.get(probe)
                    if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                        try:
                            import json
                            data = json.loads(resp.text)
                            if data and len(str(data)) > 50:
                                findings.append(self._finding(
                                    name="api_bola_resource_exposed",
                                    severity="high",
                                    confidence="medium",
                                    description=f"Ressource API accessible sans authentification apparente ({path}/{rid})",
                                    url=url,
                                    location=probe,
                                    evidence=f"HTTP 200 JSON — {str(data)[:200]}",
                                    impact=(
                                        "Accès non autorisé à des données utilisateurs via l'API "
                                        "(Broken Object Level Authorization)."
                                    ),
                                    recommendation=(
                                        "Valider l'identité et les droits du demandeur pour chaque "
                                        "ressource API. Implémenter des contrôles d'autorisation "
                                        "par objet (BOLA/IDOR mitigation)."
                                    ),
                                ))
                                break
                        except Exception:
                            pass
                except Exception:
                    continue

        return self._dedup(findings)
