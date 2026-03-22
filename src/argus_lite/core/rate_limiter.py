"""Rate limiter using asyncio Semaphore + token bucket."""

from __future__ import annotations

import asyncio
import time
from types import TracebackType


class RateLimiter:
    """Async context manager for rate limiting and concurrency control.

    Args:
        rps: Requests per second (0 = no rate limit).
        max_concurrent: Maximum concurrent operations.
    """

    def __init__(self, rps: int = 10, max_concurrent: int = 5) -> None:
        self._rps = rps
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> RateLimiter:
        await self._semaphore.acquire()

        if self._min_interval > 0:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_request_time
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)
                self._last_request_time = time.monotonic()

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._semaphore.release()
