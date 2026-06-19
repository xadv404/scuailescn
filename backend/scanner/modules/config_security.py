"""
Configuration Security module.

Checks:
  - Sensitive file exposure (.git, .svn, phpinfo, web.config, .htaccess…)
  - robots.txt disclosures of sensitive paths
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from backend.scanner.modules.base_module import BaseModule

_SENSITIVE_FILES = [
    ("/.git/config",      "Git repository configuration"),
    ("/.git/HEAD",        "Git HEAD reference"),
    ("/.svn/entries",     "SVN repository"),
    ("/composer.json",    "PHP Composer manifest"),
    ("/composer.lock",    "PHP Composer lock file"),
    ("/package.json",     "Node.js package manifest"),
    ("/Gemfile",          "Ruby Gemfile"),
    ("/requirements.txt", "Python requirements"),
    ("/web.config",       "ASP.NET web.config"),
    ("/.htaccess",        "Apache .htaccess"),
    ("/phpinfo.php",      "PHP info page"),
    ("/info.php",         "PHP info page"),
    ("/test.php",         "PHP test file"),
    ("/server-status",    "Apache server-status"),
    ("/server-info",      "Apache server-info"),
    ("/.DS_Store",        "macOS .DS_Store"),
]

_ROBOTS_SENSITIVE = re.compile(
    r"Disallow:\s*/?(admin|backup|db|database|config|secret|internal|private|staging|dev|test)",
    re.IGNORECASE,
)


class ConfigSecurityModule(BaseModule):
    NAME     = "config_security"
    CATEGORY = "Configuration Security"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base(url)

        # Sensitive file exposure
        for path, label in _SENSITIVE_FILES:
            probe = urljoin(base, path)
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200 and resp.text.strip():
                    self._log.warning(f"Sensitive file accessible: {probe}")
                    findings.append(self._finding(
                        type="sensitive_file_exposed",
                        severity="high",
                        confidence="confirmed",
                        description=f"Fichier sensible accessible : {path} ({label})",
                        url=url,
                        location=probe,
                        evidence=f"HTTP {resp.status_code} — {resp.text[:100].strip()[:100]}",
                        impact=(
                            f"Le fichier {path} expose des informations sur la configuration "
                            "ou l'infrastructure, facilitant la reconnaissance et l'exploitation."
                        ),
                        recommendation=(
                            f"Supprimer ou restreindre l'accès à {path}. "
                            "Configurer le serveur web pour bloquer les fichiers sensibles "
                            "(règle .htaccess ou nginx deny)."
                        ),
                    ))
            except Exception:
                continue

        # robots.txt
        robots_url = urljoin(base, "/robots.txt")
        try:
            resp = await self._client.get(robots_url)
            if resp.status_code == 200:
                for m in _ROBOTS_SENSITIVE.finditer(resp.text):
                    findings.append(self._finding(
                        type="sensitive_path_in_robots",
                        severity="info",
                        confidence="confirmed",
                        description="Chemin sensible référencé dans robots.txt",
                        url=url,
                        location=robots_url,
                        evidence=m.group(0)[:200],
                        impact=(
                            "robots.txt est public et liste des chemins à ne pas indexer — "
                            "souvent des zones d'administration ou sensibles."
                        ),
                        recommendation=(
                            "Ne pas lister les chemins sensibles dans robots.txt. "
                            "Protéger les zones sensibles par authentification."
                        ),
                    ))
                    break
        except Exception:
            pass

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
