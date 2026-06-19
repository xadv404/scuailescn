"""
Sensitive Data Exposure module.

Detects:
  - Server/technology version headers
  - Stack traces and verbose error messages
  - Email addresses, phone numbers, card patterns in responses
  - Sensitive configuration/source files exposed
  - robots.txt path disclosures
  - Internal IP addresses / hostnames
"""
import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from backend.scanner.modules.base_module import BaseModule

_TECH_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Backend-Server", "X-Runtime", "X-Drupal-Cache",
]

_STACK_TRACE_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        r"Traceback \(most recent call last\)",
        r'File "[^"]+\.py", line \d+',
        r"at\s+[\w\.]+\([\w\.]+:\d+\)",
        r"Stack trace:",
        r"<b>Fatal error</b>",
        r"Warning:.*in /.+\.php on line \d+",
        r"com\.[\w\.]+Exception",
        r"org\.springframework\.web",
        r"javax\.servlet\.ServletException",
    ]
]

_SENSITIVE_FILE_PATHS = [
    ("/.git/config",      "Git repository config"),
    ("/.git/HEAD",        "Git HEAD"),
    ("/.svn/entries",     "SVN repository"),
    ("/composer.json",    "PHP Composer manifest"),
    ("/package.json",     "Node.js package manifest"),
    ("/web.config",       "ASP.NET web.config"),
    ("/.htaccess",        "Apache .htaccess"),
    ("/phpinfo.php",      "PHP info page"),
    ("/info.php",         "PHP info page"),
    ("/server-status",    "Apache server-status"),
    ("/Gemfile",          "Ruby Gemfile"),
    ("/requirements.txt", "Python requirements"),
]

_EMAIL_RE  = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_CARD_RE   = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")
_PRIVIP_RE = re.compile(
    r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
)
_ROBOTS_SENSITIVE_RE = re.compile(
    r"Disallow:\s*/?(admin|backup|db|database|config|secret|internal|private|staging|test|dev)",
    re.IGNORECASE,
)


class SensitiveDataModule(BaseModule):
    NAME     = "sensitive_data"
    CATEGORY = "Sensitive Data Exposure"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base_url(url)

        try:
            resp = await self._client.get(url)
        except Exception:
            return findings

        body    = resp.text[:15000]
        headers = resp.headers

        # 1. Tech/version headers
        exposed_hdrs = [f"{h}: {headers.get(h)}" for h in _TECH_HEADERS if headers.get(h)]
        if exposed_hdrs:
            findings.append(self._finding(
                name="server_version_disclosed",
                severity="low",
                confidence="confirmed",
                description="Informations de version exposées dans les en-têtes HTTP",
                url=url,
                evidence="\n".join(exposed_hdrs),
                impact=(
                    "Permet à un attaquant de cibler des CVE connues "
                    "pour la technologie et la version exposée."
                ),
                recommendation=(
                    "Masquer les en-têtes Server, X-Powered-By et similaires "
                    "dans la configuration du serveur web."
                ),
            ))

        # 2. Stack traces
        for pat in _STACK_TRACE_RE:
            m = pat.search(body)
            if m:
                findings.append(self._finding(
                    name="stack_trace_exposed",
                    severity="medium",
                    confidence="confirmed",
                    description="Trace d'erreur technique exposée dans la réponse",
                    url=url,
                    evidence=m.group(0)[:300],
                    impact=(
                        "Révèle des chemins de fichiers, noms de classes, technologies "
                        "utilisées — facilite la reconnaissance et l'exploitation."
                    ),
                    recommendation=(
                        "Configurer des gestionnaires d'exceptions globaux avec pages d'erreur "
                        "génériques. Désactiver le mode debug en production."
                    ),
                ))
                break

        # 3. Sensitive patterns in body
        em = _EMAIL_RE.findall(body[:5000])
        internal_emails = [e for e in em if not e.endswith((".png", ".jpg", ".css"))]
        if len(internal_emails) > 3:
            findings.append(self._finding(
                name="email_addresses_exposed",
                severity="info",
                confidence="confirmed",
                description=f"{len(internal_emails)} adresses e-mail exposées dans la page",
                url=url,
                evidence=", ".join(internal_emails[:5]),
                impact=(
                    "Les adresses e-mail exposées facilitent le phishing ciblé "
                    "et les attaques par credential stuffing."
                ),
                recommendation=(
                    "Masquer ou obfusquer les adresses e-mail dans le HTML public. "
                    "Utiliser des formulaires de contact à la place."
                ),
            ))

        # Credit card patterns (red flag)
        cc_m = _CARD_RE.search(body)
        if cc_m:
            findings.append(self._finding(
                name="credit_card_pattern_exposed",
                severity="critical",
                confidence="medium",
                description="Pattern de numéro de carte bancaire détecté dans la réponse",
                url=url,
                evidence=f"Pattern : {cc_m.group(0)[:8]}****",
                impact="Exposition possible de données PCI-DSS — implications légales majeures.",
                recommendation=(
                    "Vérifier immédiatement que des données de carte ne sont pas exposées. "
                    "Mettre en place un audit PCI-DSS complet."
                ),
            ))

        # Private IP addresses
        ip_m = _PRIVIP_RE.search(body[:5000])
        if ip_m:
            findings.append(self._finding(
                name="internal_ip_disclosed",
                severity="low",
                confidence="confirmed",
                description=f"Adresse IP interne exposée dans la réponse",
                url=url,
                evidence=ip_m.group(0),
                impact=(
                    "Révèle la topologie réseau interne — facilite la reconnaissance "
                    "et le pivoting en cas de compromission."
                ),
                recommendation=(
                    "Supprimer les références aux adresses IP internes du code et "
                    "des messages d'erreur."
                ),
            ))

        # 4. Sensitive files
        for path, label in _SENSITIVE_FILE_PATHS:
            probe = f"{base}{path}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and r.text.strip():
                    findings.append(self._finding(
                        name="sensitive_file_exposed",
                        severity="high",
                        confidence="confirmed",
                        description=f"Fichier sensible accessible : {path} ({label})",
                        url=url,
                        location=probe,
                        evidence=r.text[:150].strip(),
                        impact=(
                            f"Exposure de {label} — informations de configuration ou "
                            "de structure de l'application accessibles publiquement."
                        ),
                        recommendation=(
                            f"Supprimer ou bloquer l'accès à {path}. "
                            "Configurer le serveur pour refuser l'accès aux fichiers sensibles."
                        ),
                    ))
            except Exception:
                continue

        # 5. robots.txt sensitive paths
        try:
            robots_url = f"{base}/robots.txt"
            r = await self._client.get(robots_url)
            if r.status_code == 200:
                for m in _ROBOTS_SENSITIVE_RE.finditer(r.text):
                    findings.append(self._finding(
                        name="sensitive_path_in_robots",
                        severity="info",
                        confidence="confirmed",
                        description="Chemin sensible référencé dans robots.txt",
                        url=url,
                        location=robots_url,
                        evidence=m.group(0)[:200],
                        impact="Robots.txt révèle des zones protégées ou sensibles.",
                        recommendation=(
                            "Ne pas lister les chemins sensibles dans robots.txt. "
                            "Sécuriser les zones par authentification, pas par obscurité."
                        ),
                    ))
                    break
        except Exception:
            pass

        return self._dedup(findings)
