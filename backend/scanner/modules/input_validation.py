"""
Input Validation module.

Parses HTML forms with BeautifulSoup to detect:
  - POST forms without apparent CSRF protection
  - File upload inputs
  - Password fields transmitted via GET
"""
from typing import Any, Dict, List
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

from backend.scanner.modules.base_module import BaseModule


class InputValidationModule(BaseModule):
    NAME     = "input_validation"
    CATEGORY = "Input Validation"

    _CSRF_NAMES = frozenset({
        "csrf", "csrftoken", "_token", "csrf_token",
        "__requestverificationtoken", "antiforgerytoken",
        "xsrf-token", "_csrf", "authenticity_token",
    })

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        if not _BS4_AVAILABLE:
            return []

        findings: List[Dict[str, Any]] = []
        try:
            resp = await self._client.get(url)
            body = resp.text
        except Exception as exc:
            self._log.debug(f"InputValidation GET error: {exc}")
            return findings

        soup = BeautifulSoup(body, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "get") or "get").lower()
            inputs = form.find_all("input")
            form_loc = urljoin(url, action) if action else url

            has_csrf = any(
                (inp.get("name") or "").lower().strip() in self._CSRF_NAMES
                for inp in inputs
                if (inp.get("type") or "").lower() == "hidden"
            )

            if not has_csrf and method == "post":
                findings.append(self._finding(
                    type="missing_csrf_token",
                    severity="medium",
                    confidence="medium",
                    description="Formulaire POST sans jeton CSRF apparent",
                    url=url,
                    location=form_loc,
                    evidence=f"action={action!r} method=POST — aucun champ CSRF masqué trouvé",
                    impact=(
                        "Sans protection CSRF, un attaquant peut forger des requêtes "
                        "authentifiées au nom d'un utilisateur connecté."
                    ),
                    recommendation=(
                        "Ajouter un jeton CSRF imprévisible à chaque formulaire POST "
                        "et le valider côté serveur avant tout traitement."
                    ),
                ))

            for inp in inputs:
                if (inp.get("type") or "").lower() == "file":
                    findings.append(self._finding(
                        type="file_upload_present",
                        severity="low",
                        confidence="confirmed",
                        description="Champ d'envoi de fichier détecté",
                        url=url,
                        location=form_loc,
                        evidence=f"input[name={inp.get('name', '?')!r} type=file]",
                        impact=(
                            "Les fonctionnalités d'upload sans validation de type/contenu "
                            "peuvent permettre l'exécution de fichiers malveillants."
                        ),
                        recommendation=(
                            "Valider l'extension, le type MIME et le contenu des fichiers uploadés. "
                            "Stocker hors de la racine web. Ne jamais exécuter les fichiers uploadés."
                        ),
                    ))
                    break

            if method == "get":
                for inp in inputs:
                    if (inp.get("type") or "").lower() == "password":
                        findings.append(self._finding(
                            type="password_in_get_form",
                            severity="high",
                            confidence="confirmed",
                            description="Champ mot de passe transmis via méthode GET",
                            url=url,
                            location=form_loc,
                            evidence="form[method=GET] contient input[type=password]",
                            impact=(
                                "Les mots de passe transmis en GET apparaissent dans les logs "
                                "du serveur, les historiques de navigation et les en-têtes Referer."
                            ),
                            recommendation=(
                                "Utiliser exclusivement POST pour les formulaires "
                                "contenant des champs de type mot de passe."
                            ),
                        ))
                        break

        return findings
