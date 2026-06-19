"""
Shared async HTTP client for passive scanning modules.
Respects the scan configuration (User-Agent, headers, cookies, auth, timeout).
"""
from typing import Any, Dict, Optional

import httpx


class AuditHttpClient:
    """Thin wrapper around httpx.AsyncClient configured from a scan config dict."""

    _DEFAULT_UA      = "SQLAuditScanner/1.0 (Authorized Security Audit)"
    _DEFAULT_TIMEOUT = 20

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        cfg = config or {}
        timeout = int(cfg.get("timeout", self._DEFAULT_TIMEOUT))

        headers: Dict[str, str] = {
            "User-Agent": cfg.get("user_agent") or self._DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,en;q=0.5",
        }

        if cfg.get("auth_bearer"):
            headers["Authorization"] = f"Bearer {cfg['auth_bearer']}"

        custom = cfg.get("headers", {})
        if isinstance(custom, dict):
            headers.update(custom)
        elif isinstance(custom, str):
            for line in custom.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()

        cookies: Dict[str, str] = {}
        raw_cookies = cfg.get("cookies", "") or ""
        for part in raw_cookies.split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                cookies[k.strip()] = v.strip()

        self._client = httpx.AsyncClient(
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # audit context; certs may be self-signed
        )

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self._client.post(url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        return await self._client.head(url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AuditHttpClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
