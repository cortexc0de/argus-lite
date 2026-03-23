"""TDD: Tests for concurrent subtask execution."""

import asyncio
import time

import pytest


class TestConcurrentSubtasks:
    def test_parallel_runs_faster_than_sequential(self):
        """Parallel execution of 3 tasks (0.1s each) should take ~0.1s, not 0.3s."""
        from argus_lite.core.concurrent import run_parallel

        results = []

        async def task_a():
            await asyncio.sleep(0.1)
            results.append("a")

        async def task_b():
            await asyncio.sleep(0.1)
            results.append("b")

        async def task_c():
            await asyncio.sleep(0.1)
            results.append("c")

        start = time.monotonic()
        asyncio.get_event_loop().run_until_complete(
            run_parallel([task_a(), task_b(), task_c()])
        )
        elapsed = time.monotonic() - start

        assert len(results) == 3
        assert elapsed < 0.3  # Should be ~0.1s, not 0.3s

    def test_one_failure_doesnt_stop_others(self):
        from argus_lite.core.concurrent import run_parallel

        results = []

        async def good():
            await asyncio.sleep(0.05)
            results.append("ok")

        async def bad():
            raise RuntimeError("boom")

        errors = asyncio.get_event_loop().run_until_complete(
            run_parallel([good(), bad(), good()])
        )

        assert len(results) == 2
        assert len(errors) == 1
        assert "boom" in errors[0]

    def test_empty_list(self):
        from argus_lite.core.concurrent import run_parallel

        errors = asyncio.get_event_loop().run_until_complete(run_parallel([]))
        assert errors == []

    def test_all_fail_returns_all_errors(self):
        from argus_lite.core.concurrent import run_parallel

        async def bad1():
            raise ValueError("err1")

        async def bad2():
            raise TypeError("err2")

        errors = asyncio.get_event_loop().run_until_complete(
            run_parallel([bad1(), bad2()])
        )
        assert len(errors) == 2
