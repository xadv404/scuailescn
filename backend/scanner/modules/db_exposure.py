"""
Database Exposure module.

Checks for:
  - Publicly accessible DB admin panels (phpMyAdmin, Adminer, pgAdmin…)
  - SQL dump / backup files accessible via HTTP
  - Database configuration files with credentials
"""
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from backend.scanner.modules.base_module import BaseModule

_ADMIN_PATHS = [
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/phpMyAdmin",
    "/adminer", "/adminer.php", "/db", "/dbadmin",
    "/mysqladmin", "/pgadmin", "/pgadmin4",
    "/mssql", "/sql", "/sqladmin", "/dbmanager", "/database",
]

_BACKUP_PATHS = [
    "/backup.sql", "/backup.sql.gz", "/dump.sql", "/database.sql",
    "/db.sql", "/db_backup.sql", "/backup/database.sql",
    "/data/backup.sql", "/www.sql", "/site.sql", "/mysql.sql",
]

_CONFIG_PATHS = [
    "/config.php", "/wp-config.php", "/configuration.php",
    "/settings.php", "/database.php", "/db.php", "/dbconfig.php",
    "/app/config/database.yml", "/config/database.yml",
    "/application.properties", "/.env", "/.env.local", "/.env.production",
]

_ADMIN_KEYWORDS = ("phpmyadmin", "adminer", "pgadmin", "database manager",
                   "mysql", "postgresql", "mariadb")
_BACKUP_KEYWORDS = ("create table", "insert into", "-- mysql",
                    "-- postgresql", "-- sqlite", "mysqldump")
_CONFIG_KEYWORDS = ("password", "db_pass", "database_url", "db_host",
                    "db_name", "secret_key", "db_user", "db_password",
                    "mysql://", "postgresql://")


class DBExposureModule(BaseModule):
    NAME     = "db_exposure"
    CATEGORY = "Database Exposure"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        base = self._base(url)

        # Admin panels
        for path in _ADMIN_PATHS:
            probe = urljoin(base, path)
            try:
                resp = await self._client.get(probe)
                if resp.status_code in (200, 301, 302):
                    sample = resp.text[:3000].lower()
                    if any(kw in sample for kw in _ADMIN_KEYWORDS):
                        findings.append(self._finding(
                            type="db_admin_panel_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Interface d'administration DB accessible ({path})",
                            url=url,
                            location=probe,
                            evidence=f"HTTP {resp.status_code} — interface DB détectée",
                            impact=(
                                "Une interface d'administration de base de données exposée "
                                "permet de parcourir, modifier ou supprimer toutes les données."
                            ),
                            recommendation=(
                                "Restreindre l'accès aux interfaces d'administration DB par "
                                "adresse IP, VPN ou authentification forte. "
                                "Ne jamais exposer ces interfaces sur Internet."
                            ),
                        ))
                        break
            except Exception:
                continue

        # Backup files
        for path in _BACKUP_PATHS:
            probe = urljoin(base, path)
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200:
                    sample = resp.text[:500].lower()
                    if any(kw in sample for kw in _BACKUP_KEYWORDS):
                        findings.append(self._finding(
                            type="db_backup_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Fichier de sauvegarde SQL accessible ({path})",
                            url=url,
                            location=probe,
                            evidence=sample[:300],
                            impact=(
                                "Un dump SQL public expose l'ensemble des données — mots de passe "
                                "hashés, PII et données métier confidentielles inclus."
                            ),
                            recommendation=(
                                "Supprimer immédiatement les fichiers de sauvegarde de la racine web. "
                                "Stocker les sauvegardes dans un emplacement sécurisé hors ligne."
                            ),
                        ))
            except Exception:
                continue

        # Config files with credentials
        for path in _CONFIG_PATHS:
            probe = urljoin(base, path)
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200:
                    sample = resp.text[:1000].lower()
                    if any(kw in sample for kw in _CONFIG_KEYWORDS):
                        findings.append(self._finding(
                            type="db_config_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Fichier de configuration avec credentials DB ({path})",
                            url=url,
                            location=probe,
                            evidence=f"HTTP {resp.status_code} — credentials détectés dans {path}",
                            impact=(
                                "Le fichier de configuration expose des identifiants de base de données, "
                                "permettant un accès direct au SGBD."
                            ),
                            recommendation=(
                                "Déplacer les fichiers de configuration hors de la racine web. "
                                "Utiliser des variables d'environnement pour les secrets. "
                                "Restreindre les permissions fichiers (chmod 600)."
                            ),
                        ))
            except Exception:
                continue

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
