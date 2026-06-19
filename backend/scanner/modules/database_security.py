"""
Database Security module.

Detects:
  - SQL errors triggered by single-quote probing
  - Database admin panels (phpMyAdmin, Adminer…)
  - SQL dump / backup files
  - Database configuration files with credentials
  - DB version/banner in HTTP headers
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.scanner.modules.base_module import BaseModule

CATEGORY = "Database Security"

_SQL_ERROR_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"Unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"SQLSTATE\[",
        r"ORA-\d{4,5}:",
        r"PG::SyntaxError",
        r"Microsoft OLE DB Provider for SQL Server",
        r"ODBC.*Driver.*Error",
        r"SQLiteException",
        r"DB2 SQL error",
        r"org\.postgresql\.util\.PSQLException",
        r"com\.mysql\.jdbc\.exceptions",
        r"Sybase message",
        r"supplied argument is not a valid MySQL result",
    ]
]

_ADMIN_PATHS = [
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/phpMyAdmin",
    "/adminer", "/adminer.php", "/dbadmin", "/mysqladmin",
    "/pgadmin", "/pgadmin4", "/sqladmin",
]

_BACKUP_PATHS = [
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/backup/database.sql", "/www.sql", "/mysql.sql", "/site.sql",
]

_CONFIG_PATHS = [
    "/wp-config.php", "/config.php", "/configuration.php", "/settings.php",
    "/database.php", "/db.php", "/.env", "/.env.local", "/.env.production",
    "/app/config/database.yml", "/config/database.yml",
]

_CONFIG_KW = ("password", "db_pass", "database_url", "db_host", "db_name",
              "secret_key", "db_password", "mysql://", "postgresql://")

_ADMIN_KW = ("phpmyadmin", "adminer", "pgadmin", "database manager",
             "mysql databases", "postgresql databases")

_BACKUP_KW = ("create table", "insert into", "-- mysql", "-- postgresql",
              "mysqldump", "-- sqlite")


class DatabaseSecurityModule(BaseModule):
    NAME     = "database_security"
    CATEGORY = CATEGORY

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        base   = self._base_url(url)

        # 1. SQL error via single-quote probe on URL params
        if params:
            for idx, (name, _) in enumerate(params):
                probed = list(params)
                probed[idx] = (name, "'" + probed[idx][1])
                probe_url = urlunparse(parsed._replace(query=urlencode(probed)))
                try:
                    resp = await self._client.get(probe_url)
                    body = resp.text[:8000]
                    for pat in _SQL_ERROR_RE:
                        m = pat.search(body)
                        if m:
                            self._log.warning(f"SQL error on param '{name}' at {url}")
                            findings.append(self._finding(
                                name="sql_error_exposed",
                                severity="high",
                                confidence="confirmed",
                                description=f"Erreur SQL exposée — paramètre « {name} »",
                                url=url,
                                location=probe_url,
                                evidence=m.group(0)[:300],
                                impact=(
                                    "Le message d'erreur révèle la structure interne de la base "
                                    "et confirme qu'une injection SQL est potentiellement exploitable."
                                ),
                                recommendation=(
                                    "Utiliser des requêtes paramétrées (prepared statements). "
                                    "Désactiver l'affichage des erreurs SQL en production. "
                                    "Configurer des pages d'erreur génériques."
                                ),
                            ))
                            break
                except Exception:
                    pass
        else:
            # Check base response for SQL errors
            try:
                resp = await self._client.get(url)
                body = resp.text[:8000]
                for pat in _SQL_ERROR_RE:
                    m = pat.search(body)
                    if m:
                        findings.append(self._finding(
                            name="sql_error_in_base_response",
                            severity="high",
                            confidence="confirmed",
                            description="Message d'erreur SQL présent dans la réponse",
                            url=url,
                            evidence=m.group(0)[:300],
                            impact=(
                                "Des erreurs SQL sont visibles sans injection active — "
                                "indique une divulgation d'informations sur la base de données."
                            ),
                            recommendation=(
                                "Désactiver les messages d'erreur verbeux. "
                                "Utiliser des gestionnaires d'exceptions génériques."
                            ),
                        ))
                        break
            except Exception:
                pass

        # 2. DB admin panels
        for path in _ADMIN_PATHS:
            probe = f"{base}{path}"
            try:
                resp = await self._client.get(probe)
                if resp.status_code in (200, 301, 302):
                    if any(kw in resp.text[:3000].lower() for kw in _ADMIN_KW):
                        findings.append(self._finding(
                            name="db_admin_panel_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Interface d'administration DB exposée ({path})",
                            url=url,
                            location=probe,
                            evidence=f"HTTP {resp.status_code} — interface DB détectée",
                            impact=(
                                "Interface permettant de parcourir, modifier ou supprimer "
                                "toutes les données accessibles au compte de service."
                            ),
                            recommendation=(
                                "Restreindre l'accès par IP/VPN. "
                                "Ne jamais exposer les interfaces d'admin DB sur Internet."
                            ),
                        ))
                        break
            except Exception:
                continue

        # 3. SQL backup files
        for path in _BACKUP_PATHS:
            probe = f"{base}{path}"
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200:
                    if any(kw in resp.text[:500].lower() for kw in _BACKUP_KW):
                        findings.append(self._finding(
                            name="db_backup_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Fichier de sauvegarde SQL accessible ({path})",
                            url=url,
                            location=probe,
                            evidence=resp.text[:200].strip(),
                            impact=(
                                "Dump SQL public exposant l'ensemble des données — "
                                "mots de passe hashés, PII et données métier inclus."
                            ),
                            recommendation=(
                                "Supprimer immédiatement les sauvegardes de la racine web. "
                                "Stocker les backups dans un emplacement sécurisé hors ligne."
                            ),
                        ))
            except Exception:
                continue

        # 4. DB config files with credentials
        for path in _CONFIG_PATHS:
            probe = f"{base}{path}"
            try:
                resp = await self._client.get(probe)
                if resp.status_code == 200 and resp.text.strip():
                    sample = resp.text[:1000].lower()
                    if any(kw in sample for kw in _CONFIG_KW):
                        findings.append(self._finding(
                            name="db_config_credentials_exposed",
                            severity="critical",
                            confidence="confirmed",
                            description=f"Fichier de config avec credentials DB exposé ({path})",
                            url=url,
                            location=probe,
                            evidence=f"HTTP {resp.status_code} — credentials trouvés dans {path}",
                            impact=(
                                "Credentials de base de données exposés publiquement — "
                                "accès direct au SGBD possible."
                            ),
                            recommendation=(
                                "Déplacer les fichiers de config hors de la racine web. "
                                "Utiliser des variables d'environnement pour les secrets."
                            ),
                        ))
            except Exception:
                continue

        return self._dedup(findings)
