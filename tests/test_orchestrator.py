"""TDD: Tests for scan orchestrator — written BEFORE implementation."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.tool_runner import ToolOutput


def _mock_tool_output(stdout: str = "", returncode: int = 0) -> ToolOutput:
    return ToolOutput(
        returncode=returncode, stdout=stdout, stderr="",
        duration_seconds=0.1, command=["mock"],
    )


class TestOrchestrator:
    def test_create_orchestrator(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)
        assert orch.target == "example.com"

    def test_run_returns_scan_result(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        # Mock all tool runners to avoid actual execution
        with patch.object(orch, "_run_recon", new_callable=AsyncMock) as mock_recon, \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock) as mock_analysis:
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.target == "example.com"
        assert result.scan_id  # UUID generated
        assert result.status in ("completed", "interrupted", "failed")

    def test_scan_result_has_started_at(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.started_at is not None
        assert result.completed_at is not None

    def test_records_completed_stages(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert "recon" in result.completed_stages
        assert "analysis" in result.completed_stages

    def test_stage_error_recorded_not_crash(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        async def failing_recon():
            raise RuntimeError("dig crashed")

        with patch.object(orch, "_run_recon", side_effect=failing_recon), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        # Should not crash, should record error
        assert len(result.errors) >= 1
        assert result.errors[0].stage == "recon"
        assert "dig crashed" in result.errors[0].message
        assert result.status == "completed"  # Still completes other stages

    def test_tools_used_tracked(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert isinstance(result.tools_used, list)


class TestGracefulShutdown:
    def test_shutdown_flag(self):
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.config import AppConfig

        orch = ScanOrchestrator(target="example.com", config=AppConfig())
        assert orch.shutdown_requested is False
        orch.request_shutdown()
        assert orch.shutdown_requested is True

    def test_shutdown_produces_interrupted_status(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        async def slow_recon():
            orch.request_shutdown()  # Simulate SIGINT during recon

        with patch.object(orch, "_run_recon", side_effect=slow_recon), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.status == "interrupted"
        assert "analysis" in result.skipped_stages


class TestProgressCallback:
    def test_progress_callback_called(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        events: list[str] = []

        def on_progress(stage: str, status: str):
            events.append(f"{stage}:{status}")

        orch = ScanOrchestrator(
            target="example.com", config=config, on_progress=on_progress
        )

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            asyncio.get_event_loop().run_until_complete(orch.run())

        assert any("recon:start" in e for e in events)
        assert any("recon:done" in e for e in events)
