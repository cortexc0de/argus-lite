"""TDD: Tests for rate limiter — written BEFORE implementation."""

import asyncio
import time

import pytest


class TestRateLimiter:
    def test_allows_within_limit(self):
        from argus_lite.core.rate_limiter import RateLimiter

        limiter = RateLimiter(rps=10, max_concurrent=5)

        async def run():
            async with limiter:
                return True

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result is True

    def test_concurrency_limit(self):
        from argus_lite.core.rate_limiter import RateLimiter

        limiter = RateLimiter(rps=100, max_concurrent=2)
        active = 0
        max_active = 0

        async def task():
            nonlocal active, max_active
            async with limiter:
                active += 1
                max_active = max(max_active, active)
                await asyncio.sleep(0.05)
                active -= 1

        async def run():
            await asyncio.gather(*[task() for _ in range(6)])

        asyncio.get_event_loop().run_until_complete(run())
        assert max_active <= 2

    def test_rate_limiting_enforced(self):
        from argus_lite.core.rate_limiter import RateLimiter

        # 5 rps means ~200ms between requests
        limiter = RateLimiter(rps=5, max_concurrent=10)
        timestamps: list[float] = []

        async def task():
            async with limiter:
                timestamps.append(time.monotonic())

        async def run():
            await asyncio.gather(*[task() for _ in range(5)])

        asyncio.get_event_loop().run_until_complete(run())
        # With 5 tasks at 5 rps, should take at least ~0.6s (not instant)
        duration = timestamps[-1] - timestamps[0]
        assert duration >= 0.5

    def test_zero_rps_disables_rate_limit(self):
        """rps=0 means no rate limiting, only concurrency."""
        from argus_lite.core.rate_limiter import RateLimiter

        limiter = RateLimiter(rps=0, max_concurrent=5)

        async def run():
            async with limiter:
                return True

        result = asyncio.get_event_loop().run_until_complete(run())
        assert result is True
