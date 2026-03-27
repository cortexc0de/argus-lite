"""Browser Agent — Playwright-based automation for SPA/JS testing.

Provides headless browser for: JS endpoint discovery, API call capture,
WebSocket interception, form interaction, cookie extraction.

Requires: pip install argus-lite[browser]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CapturedRequest:
    """An XHR/fetch request captured during browser navigation."""

    method: str = "GET"
    url: str = ""
    post_data: str = ""
    resource_type: str = ""


@dataclass
class CapturedWebSocket:
    """A WebSocket message captured during navigation."""

    url: str = ""
    direction: str = ""  # "sent" or "received"
    payload: str = ""


class BrowserAgent:
    """Playwright-based browser automation for SPA testing."""

    def __init__(self) -> None:
        self._browser = None
        self._page = None
        self._api_calls: list[CapturedRequest] = []
        self._ws_messages: list[CapturedWebSocket] = []
        self._running = False

    @staticmethod
    def is_available() -> bool:
        """Check if playwright is installed."""
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    async def start(self, headless: bool = True) -> None:
        """Launch browser and create page with network interception."""
        if not self.is_available():
            logger.warning("Playwright not installed. Install with: pip install argus-lite[browser]")
            return

        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=headless)
        self._page = await self._browser.new_page()

        # Intercept XHR/fetch requests
        self._page.on("request", self._on_request)
        self._page.on("websocket", self._on_websocket)
        self._running = True

    def _on_request(self, request) -> None:
        """Capture API calls (XHR, fetch)."""
        if request.resource_type in ("xhr", "fetch"):
            self._api_calls.append(CapturedRequest(
                method=request.method,
                url=request.url,
                post_data=request.post_data or "",
                resource_type=request.resource_type,
            ))

    def _on_websocket(self, ws) -> None:
        """Capture WebSocket connections."""
        ws.on("framesent", lambda payload: self._ws_messages.append(
            CapturedWebSocket(url=ws.url, direction="sent", payload=str(payload))
        ))
        ws.on("framereceived", lambda payload: self._ws_messages.append(
            CapturedWebSocket(url=ws.url, direction="received", payload=str(payload))
        ))

    async def navigate(self, url: str) -> int:
        """Navigate to URL and wait for network idle. Returns status code."""
        if not self._page:
            return 0
        resp = await self._page.goto(url, wait_until="networkidle", timeout=30000)
        return resp.status if resp else 0

    async def login(self, url: str, username_sel: str, password_sel: str, creds: dict) -> bool:
        """Fill login form and submit."""
        if not self._page:
            return False
        await self._page.goto(url, wait_until="networkidle")
        await self._page.fill(username_sel, creds.get("username", ""))
        await self._page.fill(password_sel, creds.get("password", ""))
        await self._page.press(password_sel, "Enter")
        await self._page.wait_for_load_state("networkidle")
        return self._page.url != url  # redirected = login success

    async def get_cookies(self) -> list[dict]:
        """Return all cookies from the current browser context."""
        if not self._page:
            return []
        return await self._page.context.cookies()

    async def get_js_endpoints(self) -> list[str]:
        """Extract API endpoints from page JavaScript sources."""
        if not self._page:
            return []
        scripts = await self._page.evaluate("""
            () => Array.from(document.querySelectorAll('script[src]'))
                       .map(s => s.src)
        """)
        endpoints: list[str] = []
        for src in scripts:
            try:
                resp = await self._page.context.request.get(src)
                text = await resp.text()
                # Extract URL patterns from JS
                urls = re.findall(r'["\']/(api|v\d+|graphql|ws)[^"\']*["\']', text)
                endpoints.extend(u.strip("\"'") for u in urls)
            except Exception:
                pass
        return list(set(endpoints))

    async def get_dom_inputs(self) -> list[dict]:
        """Extract all form inputs from the current page."""
        if not self._page:
            return []
        return await self._page.evaluate("""
            () => Array.from(document.querySelectorAll('input, textarea, select'))
                       .map(el => ({
                           tag: el.tagName,
                           type: el.type || '',
                           name: el.name || '',
                           id: el.id || '',
                           value: el.value || '',
                       }))
        """)

    def get_api_calls(self) -> list[CapturedRequest]:
        """Return captured XHR/fetch requests."""
        return list(self._api_calls)

    def get_websocket_messages(self) -> list[CapturedWebSocket]:
        """Return captured WebSocket messages."""
        return list(self._ws_messages)

    async def close(self) -> None:
        """Close browser."""
        if self._browser:
            await self._browser.close()
        if hasattr(self, "_pw") and self._pw:
            await self._pw.stop()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running
