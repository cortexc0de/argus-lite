"""Concurrent subtask execution with error isolation."""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def run_parallel(coros: list) -> list[str]:
    """Run coroutines in parallel. Errors are collected, not raised.

    Returns a list of error messages (empty if all succeeded).
    Each coroutine runs independently — one failure doesn't stop others.
    """
    if not coros:
        return []

    errors: list[str] = []

    async def _safe(coro):
        try:
            await coro
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            logger.warning("Parallel subtask failed: %s", msg)
            errors.append(msg)

    await asyncio.gather(*[_safe(c) for c in coros])
    return errors
