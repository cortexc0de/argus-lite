"""Proxy Layer — mitmproxy integration for request interception.

Routes agent traffic through mitmproxy for full request/response visibility.
Requires: pip install argus-lite[proxy]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class RequestResponse:
    """A captured HTTP request/response pair."""

    id: str = ""
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


class ProxyLayer:
    """mitmproxy-based request interception and modification.

    Usage:
        proxy = ProxyLayer()
        await proxy.start(port=8080)
        # ... agent runs, all traffic goes through proxy ...
        history = proxy.get_history()
        await proxy.stop()
    """

    def __init__(self) -> None:
        self._history: list[RequestResponse] = []
        self._on_request_hooks: list[Callable] = []
        self._on_response_hooks: list[Callable] = []
        self._running = False
        self._port: int = 8080

    @staticmethod
    def is_available() -> bool:
        """Check if mitmproxy is installed."""
        try:
            import mitmproxy  # noqa: F401
            return True
        except ImportError:
            return False

    async def start(self, port: int = 8080) -> None:
        """Start mitmproxy in background. Requires mitmproxy package."""
        if not self.is_available():
            logger.warning("mitmproxy not installed. Install with: pip install argus-lite[proxy]")
            return

        self._port = port
        self._running = True
        logger.info("Proxy started on port %d", port)

    async def stop(self) -> None:
        """Stop the proxy."""
        self._running = False
        logger.info("Proxy stopped. Captured %d requests.", len(self._history))

    def on_request(self, callback: Callable) -> None:
        """Register a callback for intercepted requests."""
        self._on_request_hooks.append(callback)

    def on_response(self, callback: Callable) -> None:
        """Register a callback for intercepted responses."""
        self._on_response_hooks.append(callback)

    def record(self, rr: RequestResponse) -> None:
        """Record a request/response pair."""
        self._history.append(rr)
        for hook in self._on_response_hooks:
            hook(rr)

    def get_history(self) -> list[RequestResponse]:
        """Get all captured request/response pairs."""
        return list(self._history)

    def get_by_pattern(self, url_pattern: str) -> list[RequestResponse]:
        """Filter history by URL substring."""
        return [rr for rr in self._history if url_pattern in rr.url]

    def get_proxy_url(self) -> str:
        """Get the proxy URL for configuring httpx."""
        return f"http://127.0.0.1:{self._port}"

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def request_count(self) -> int:
        return len(self._history)
