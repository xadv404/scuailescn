"""
File Security module.

Detects:
  - Directory listing enabled
  - Backup files accessible (.bak, .old, ~, .orig, .copy)
  - Unsafe file upload endpoints
  - Log files exposed
  - Source code files accessible
  - Archive files accessible (.zip, .tar, .gz)
"""
import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from backend.scanner.modules.base_module import BaseModule

_BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".copy", ".backup",
    ".tmp", ".temp", "~", ".swp", ".save",
]

_BACKUP_FILES = [
    "/index.php.bak", "/index.php.old", "/index.html.bak",
    "/config.php.bak", "/config.php.old", "/database.php.bak",
    "/wp-config.php.bak", "/wp-config.php.old",
    "/settings.php.bak", "/application.properties.bak",
    "/.env.bak", "/.env.old", "/.env.backup",
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/site.tar.gz", "/backup.zip", "/www.zip", "/htdocs.zip",
    "/backup.tar.gz", "/archive.zip",
]

_LOG_FILES = [
    "/access.log", "/error.log", "/debug.log", "/application.log",
    "/server.log", "/app.log", "/php_errors.log",
    "/logs/access.log", "/logs/error.log", "/logs/app.log",
    "/var/log/nginx/access.log", "/var/log/apache2/access.log",
]

_SOURCE_FILES = [
    "/app.py", "/main.py", "/wsgi.py", "/settings.py",
    "/application.py", "/server.py",
    "/config.rb", "/database.rb",
    "/app.js", "/server.js", "/index.js",
]

_DIR_LISTING_RE = re.compile(
    r'(?:Index of /|Directory Listing For|Parent Directory|<title>Index of)',
    re.IGNORECASE,
)

_UPLOAD_FORM_RE = re.compile(
    r'<input[^>]+type\s*=\s*["\']file["\']',
    re.IGNORECASE,
)

_UPLOAD_PATHS = [
    "/upload", "/uploads", "/file/upload", "/api/upload",
    "/media/upload", "/files/upload", "/attachment/upload",
    "/import", "/api/import",
]


class FileSecurityModule(BaseModule):
    NAME     = "file_security"
    CATEGORY = "File Security"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base_url(url)

        try:
            resp_base = await self._client.get(url)
        except Exception:
            return findings

        body = resp_base.text[:10000]

        # 1. Directory listing on current URL
        if _DIR_LISTING_RE.search(body):
            findings.append(self._finding(
                name="directory_listing_enabled",
                severity="medium",
                confidence="confirmed",
                description="Listing de répertoire activé",
                url=url,
                evidence=_DIR_LISTING_RE.search(body).group(0)[:100],
                impact=(
                    "Le listing de répertoire expose la structure et les fichiers "
                    "de l'application — facilite la reconnaissance et l'accès à des "
                    "fichiers sensibles non liés."
                ),
                recommendation=(
                    "Désactiver l'option 'Indexes' dans Apache ou 'autoindex off' dans Nginx. "
                    "Placer un fichier index.html vide dans les répertoires."
                ),
            ))

        # 2. Check common directories for listing
        _dirs_to_check = ["/uploads/", "/files/", "/backup/", "/images/", "/static/", "/media/"]
        for dpath in _dirs_to_check:
            probe = f"{base}{dpath}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and _DIR_LISTING_RE.search(r.text[:3000]):
                    findings.append(self._finding(
                        name="directory_listing_enabled",
                        severity="medium",
                        confidence="confirmed",
                        description=f"Listing de répertoire activé sur {dpath}",
                        url=url,
                        location=probe,
                        evidence=f"HTTP 200 — listing détecté dans {dpath}",
                        impact=(
                            "Accès aux fichiers uploadés ou de sauvegarde via listing."
                        ),
                        recommendation=(
                            "Désactiver le listing de répertoire sur le serveur web."
                        ),
                    ))
            except Exception:
                pass

        # 3. Backup files
        for bpath in _BACKUP_FILES:
            probe = f"{base}{bpath}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and len(r.text.strip()) > 10:
                    findings.append(self._finding(
                        name="backup_file_exposed",
                        severity="high",
                        confidence="confirmed",
                        description=f"Fichier de sauvegarde accessible : {bpath}",
                        url=url,
                        location=probe,
                        evidence=r.text[:150].strip(),
                        impact=(
                            "Les fichiers de sauvegarde peuvent contenir des credentials, "
                            "du code source ou des données sensibles."
                        ),
                        recommendation=(
                            f"Supprimer {bpath} du serveur web. "
                            "Ne jamais laisser des fichiers de sauvegarde dans les "
                            "répertoires accessibles publiquement."
                        ),
                    ))
            except Exception:
                pass

        # 4. Log files
        for lpath in _LOG_FILES:
            probe = f"{base}{lpath}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and len(r.text.strip()) > 50:
                    ct = r.headers.get("content-type", "")
                    if "text" in ct or r.text[:100].strip().startswith(
                        ("GET ", "POST ", "[", "20", "19", "Error", "Warning")
                    ):
                        findings.append(self._finding(
                            name="log_file_exposed",
                            severity="high",
                            confidence="confirmed",
                            description=f"Fichier de log accessible publiquement : {lpath}",
                            url=url,
                            location=probe,
                            evidence=r.text[:200].strip(),
                            impact=(
                                "Les logs exposent les URLs, IPs, paramètres et potentiellement "
                                "des données d'authentification ou des tokens."
                            ),
                            recommendation=(
                                f"Déplacer les logs hors du webroot. "
                                "Configurer le serveur pour bloquer l'accès aux fichiers .log."
                            ),
                        ))
            except Exception:
                pass

        # 5. Source code files
        for spath in _SOURCE_FILES:
            probe = f"{base}{spath}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and len(r.text.strip()) > 20:
                    # Heuristic: looks like source code
                    txt = r.text[:500]
                    is_source = any(kw in txt for kw in (
                        "import ", "from ", "require(", "def ", "class ",
                        "function ", "const ", "#!/", "<?php",
                    ))
                    if is_source:
                        findings.append(self._finding(
                            name="source_code_exposed",
                            severity="critical",
                            confidence="high",
                            description=f"Code source exposé publiquement : {spath}",
                            url=url,
                            location=probe,
                            evidence=txt[:200].strip(),
                            impact=(
                                "Le code source révèle la logique applicative, les credentials "
                                "hardcodés, les clés API et les vulnérabilités internes."
                            ),
                            recommendation=(
                                f"Supprimer {spath} du webroot immédiatement. "
                                "Réviser tous les fichiers de configuration pour credentials exposés."
                            ),
                        ))
            except Exception:
                pass

        # 6. Unsafe file upload detection
        if _UPLOAD_FORM_RE.search(body):
            findings.append(self._finding(
                name="file_upload_form_detected",
                severity="info",
                confidence="confirmed",
                description="Formulaire d'upload de fichier détecté sur la page",
                url=url,
                evidence="<input type=\"file\"> présent dans le formulaire",
                impact=(
                    "Les formulaires d'upload sont des vecteurs potentiels "
                    "d'upload de webshell ou de fichiers malveillants."
                ),
                recommendation=(
                    "Valider le type MIME côté serveur. "
                    "Interdire l'exécution dans les répertoires d'upload. "
                    "Limiter les extensions autorisées. "
                    "Scanner les fichiers uploadés avec un antivirus."
                ),
            ))

        # Check upload endpoints
        for upath in _UPLOAD_PATHS:
            probe = f"{base}{upath}"
            try:
                r = await self._client.get(probe)
                if r.status_code == 200 and _UPLOAD_FORM_RE.search(r.text[:5000]):
                    findings.append(self._finding(
                        name="file_upload_endpoint",
                        severity="medium",
                        confidence="confirmed",
                        description=f"Endpoint d'upload de fichiers détecté : {upath}",
                        url=url,
                        location=probe,
                        evidence=f"HTTP 200 — formulaire d'upload présent",
                        impact=(
                            "Endpoint d'upload sans validation peut permettre l'upload "
                            "de webshells ou de fichiers malveillants."
                        ),
                        recommendation=(
                            "Implémenter une validation stricte du type et du contenu des fichiers. "
                            "Stocker les uploads hors du webroot. "
                            "Utiliser un CDN ou un service de stockage dédié."
                        ),
                    ))
            except Exception:
                pass

        return self._dedup(findings)
