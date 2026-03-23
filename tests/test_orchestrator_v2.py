"""TDD: Tests for upgraded orchestrator — preset selection + new tools."""

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
        # Quick should NOT include heavy tools
        assert "naabu" not in tools
        assert "nuclei" not in tools
        assert "ffuf" not in tools
        assert "katana" not in tools

    def test_full_preset_tools(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")
        tools = orch.get_enabled_tools()
        # Full includes everything
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
        # No active scanning
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
        # Web should not include port scan
        assert "naabu" not in tools


class TestNewToolsWired:
    def test_recon_runs_new_tools_in_full(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")

        with patch.object(orch, "_run_subtask", new_callable=AsyncMock) as mock_sub:
            asyncio.get_event_loop().run_until_complete(orch._run_recon())

        called_names = [call.args[0] for call in mock_sub.call_args_list]
        assert "dns" in called_names
        assert "whois" in called_names
        assert "httpx" in called_names
        assert "katana" in called_names
        assert "gau" in called_names
        assert "dnsx" in called_names
        assert "tlsx" in called_names

    def test_analysis_runs_ffuf_in_full(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="full")

        with patch.object(orch, "_run_subtask", new_callable=AsyncMock) as mock_sub:
            asyncio.get_event_loop().run_until_complete(orch._run_analysis())

        called_names = [call.args[0] for call in mock_sub.call_args_list]
        assert "ffuf" in called_names
        assert "nuclei" in called_names
        assert "ports" in called_names

    def test_quick_skips_heavy_tools(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig(), preset="quick")

        with patch.object(orch, "_run_subtask", new_callable=AsyncMock) as mock_sub:
            asyncio.get_event_loop().run_until_complete(orch._run_recon())

        called_names = [call.args[0] for call in mock_sub.call_args_list]
        assert "dns" in called_names
        assert "katana" not in called_names
        assert "gau" not in called_names

    def test_backward_compat_no_preset(self):
        """Default (no preset) should work like before."""
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="example.com", config=AppConfig())

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.status in ("completed", "interrupted")
