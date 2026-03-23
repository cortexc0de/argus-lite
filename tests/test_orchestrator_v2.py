"""Tests for upgraded orchestrator — preset selection + parallel execution."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from argus_lite.core.config import AppConfig


class TestPresets:
    def test_quick_preset_tools(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="quick")
        tools = orch.get_enabled_tools()
        assert "dig" in tools
        assert "whois" in tools
        assert "whatweb" in tools
        assert "naabu" not in tools
        assert "nuclei" not in tools
        assert "ffuf" not in tools
        assert "katana" not in tools

    def test_full_preset_tools(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")
        tools = orch.get_enabled_tools()
        assert "dig" in tools
        assert "naabu" in tools
        assert "nuclei" in tools
        assert "httpx" in tools
        assert "katana" in tools
        assert "ffuf" in tools
        assert "gau" in tools
        assert "dnsx" in tools
        assert "tlsx" in tools

    def test_recon_preset_passive_only(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="recon")
        tools = orch.get_enabled_tools()
        assert "dig" in tools
        assert "whois" in tools
        assert "subfinder" in tools
        assert "naabu" not in tools
        assert "nuclei" not in tools
        assert "ffuf" not in tools

    def test_web_preset_tools(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="web")
        tools = orch.get_enabled_tools()
        assert "httpx" in tools
        assert "katana" in tools
        assert "nuclei" in tools
        assert "whatweb" in tools
        assert "naabu" not in tools


class TestParallelExecution:
    def test_full_scan_completes(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.status == "completed"
        assert "recon" in result.completed_stages
        assert "analysis" in result.completed_stages

    def test_backward_compat_no_preset(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig())

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.status in ("completed", "interrupted")

    def test_recon_uses_run_parallel(self):
        """Verify run_parallel is called for grouped tasks."""
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")

        with patch("argus_lite.core.orchestrator.run_parallel", new_callable=AsyncMock) as mock_par:
            mock_par.return_value = []
            asyncio.get_event_loop().run_until_complete(orch._run_recon())

        # Should be called twice (group1 + group2)
        assert mock_par.call_count == 2

    def test_analysis_uses_run_parallel(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")

        with patch("argus_lite.core.orchestrator.run_parallel", new_callable=AsyncMock) as mock_par:
            mock_par.return_value = []
            asyncio.get_event_loop().run_until_complete(orch._run_analysis())

        assert mock_par.call_count == 1
