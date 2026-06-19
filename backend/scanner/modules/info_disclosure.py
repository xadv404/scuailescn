"""
Information Disclosure module.

Inspects response headers and body for server version strings,
stack traces, and other sensitive technical information.
"""
import re
from typing import Any, Dict, List

from backend.scanner.modules.base_module import BaseModule

_SENSITIVE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Backend-Server",
    "X-Runtime",
    "Via",
]

_STACK_TRACE_PATTERNS = [
    re.compile(r"at\s+[\w\.]+\([\w\.]+:\d+\)", re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"Stack trace:", re.IGNORECASE),
    re.compile(r'File "[^"]+\.py", line \d+', re.IGNORECASE),
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"<b>Fatal error</b>", re.IGNORECASE),
    re.compile(r"Warning:.*in\s+/.+\.php on line \d+", re.IGNORECASE),
    re.compile(r"com\.[\w\.]+Exception", re.IGNORECASE),
]


class InfoDisclosureModule(BaseModule):
    NAME     = "info_disclosure"
    CATEGORY = "Information Disclosure"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            resp = await self._client.get(url)
        except Exception as exc:
            self._log.debug(f"InfoDisclosure GET error: {exc}")
            return findings

        # Sensitive response headers
        exposed = []
        for h in _SENSITIVE_HEADERS:
            val = resp.headers.get(h)
            if val:
                exposed.append(f"{h}: {val}")

        if exposed:
            findings.append(self._finding(
                type="server_version_in_headers",
                severity="low",
                confidence="confirmed",
                description="Informations de version du serveur exposées dans les en-têtes HTTP",
                url=url,
                evidence="\n".join(exposed),
                impact=(
                    "Les informations de version permettent à un attaquant de cibler "
                    "des CVE connues pour la technologie et la version exposée."
                ),
                recommendation=(
                    "Configurer le serveur web pour supprimer ou masquer les en-têtes "
                    "Server, X-Powered-By et autres en-têtes révélant des informations "
                    "technologiques."
                ),
            ))

        # Stack traces in body
        body = resp.text[:12000]
        for pat in _STACK_TRACE_PATTERNS:
            m = pat.search(body)
            if m:
                self._log.warning(f"Stack trace detected at {url}")
                findings.append(self._finding(
                    type="stack_trace_exposed",
                    severity="medium",
                    confidence="confirmed",
                    description="Trace d'erreur ou stack trace exposée dans la réponse",
                    url=url,
                    evidence=m.group(0)[:300],
                    impact=(
                        "Les traces d'erreur révèlent des chemins de fichiers, noms de classes, "
                        "numéros de ligne et technologies utilisées, facilitant la reconnaissance."
                    ),
                    recommendation=(
                        "Configurer des gestionnaires d'exceptions globaux retournant des pages "
                        "d'erreur génériques. Désactiver le mode debug en production."
                    ),
                ))
                break

        return findings
