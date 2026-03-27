"""HTTP Session Manager — persistent cookies, auth, and headers across skills.

Provides a shared httpx.AsyncClient that maintains cookies and auth state,
so the agent can login once and all subsequent skills use the same session.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class HttpSessionManager:
    """Persistent HTTP session with cookie jar, auth, and headers."""

    def __init__(self, base_url: str = "", timeout: int = 30) -> None:
        self._base_url = base_url
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._auth_token: str | None = None
        self._extra_headers: dict[str, str] = {}
        self._authenticated: bool = False

    async def start(self) -> None:
        """Initialize the HTTP client with cookie persistence."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=self._timeout,
                verify=False,
            )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            await self.start()
        return self._client  # type: ignore[return-value]

    async def login(self, url: str, credentials: dict[str, str]) -> bool:
        """Attempt login via POST with credentials. Stores cookies on success."""
        client = await self._ensure_client()
        try:
            resp = await client.post(url, data=credentials)
            self._authenticated = resp.status_code in (200, 302, 303)
            if self._authenticated:
                logger.info("Session login successful: %s → %d", url, resp.status_code)
            return self._authenticated
        except Exception as exc:
            logger.warning("Session login failed: %s", exc)
            return False

    def set_auth_token(self, token: str, scheme: str = "Bearer") -> None:
        """Set authorization header for all subsequent requests."""
        self._auth_token = token
        self._extra_headers["Authorization"] = f"{scheme} {token}"

    def set_header(self, key: str, value: str) -> None:
        """Set a custom header for all subsequent requests."""
        self._extra_headers[key] = value

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """GET with session cookies and headers."""
        client = await self._ensure_client()
        return await client.get(url, headers=self._extra_headers, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """POST with session cookies and headers."""
        client = await self._ensure_client()
        return await client.post(url, headers=self._extra_headers, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Generic request with session cookies and headers."""
        client = await self._ensure_client()
        return await client.request(method, url, headers=self._extra_headers, **kwargs)

    def get_cookies(self) -> dict[str, str]:
        """Return current cookie jar as dict."""
        if self._client:
            return dict(self._client.cookies)
        return {}

    def has_session(self) -> bool:
        """Check if we have an active authenticated session."""
        return self._authenticated and bool(self.get_cookies())

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated
