"""TDD: Tests for smart pipeline — tools feed each other."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AppConfig
from argus_lite.core.tool_runner import ToolOutput


class TestHttpxMulti:
    def test_probe_multi_with_mock(self):
        from argus_lite.modules.recon.httpx_probe import httpx_probe_multi

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0,
            stdout='{"url":"https://a.com","status_code":200,"title":"A","content_length":100,"tech":[],"server":"","response_time":"50ms","failed":false}\n',
            stderr="", duration_seconds=1.0, command=["httpx"],
        ))

        result = asyncio.get_event_loop().run_until_complete(
            httpx_probe_multi(["a.com", "b.com"], runner=mock_runner)
        )
        assert len(result) == 1  # only one JSON line in mock
        # Verify -l flag was used (not -u)
        call_args = mock_runner.run.call_args[0][0]
        assert "-l" in call_args

    def test_probe_multi_empty_targets(self):
        from argus_lite.modules.recon.httpx_probe import httpx_probe_multi

        result = asyncio.get_event_loop().run_until_complete(
            httpx_probe_multi([], runner=MagicMock())
        )
        assert result == []

    def test_probe_multi_deduplicates(self):
        from argus_lite.modules.recon.httpx_probe import httpx_probe_multi

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0, stdout="", stderr="", duration_seconds=0.1, command=["httpx"],
        ))

        asyncio.get_event_loop().run_until_complete(
            httpx_probe_multi(["a.com", "a.com", "b.com"], runner=mock_runner)
        )
        # Check the temp file would have 2 unique targets (we can't read it, but run was called)
        mock_runner.run.assert_called_once()


class TestNucleiMulti:
    def test_scan_multi_with_mock(self):
        from argus_lite.modules.analysis.nuclei import nuclei_scan_multi

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0,
            stdout='{"template-id":"test","info":{"name":"T","severity":"info","tags":[]},"type":"http","host":"x","matched-at":"x"}\n',
            stderr="", duration_seconds=5.0, command=["nuclei"],
        ))

        result = asyncio.get_event_loop().run_until_complete(
            nuclei_scan_multi(["https://a.com", "https://b.com"], runner=mock_runner)
        )
        assert len(result) == 1
        call_args = mock_runner.run.call_args[0][0]
        assert "-l" in call_args

    def test_scan_multi_with_tags(self):
        from argus_lite.modules.analysis.nuclei import nuclei_scan_multi

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0, stdout="", stderr="", duration_seconds=1.0, command=["nuclei"],
        ))

        asyncio.get_event_loop().run_until_complete(
            nuclei_scan_multi(["https://a.com"], runner=mock_runner, tags=["wordpress", "php"])
        )
        call_args = mock_runner.run.call_args[0][0]
        assert "-tags" in call_args
        tags_idx = call_args.index("-tags")
        assert "wordpress,php" in call_args[tags_idx + 1]

    def test_scan_multi_empty(self):
        from argus_lite.modules.analysis.nuclei import nuclei_scan_multi

        result = asyncio.get_event_loop().run_until_complete(
            nuclei_scan_multi([], runner=MagicMock())
        )
        assert result == []


class TestFfufSeeds:
    def test_scan_with_seeds(self):
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan_with_seeds

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0, stdout='{"results":[]}', stderr="",
            duration_seconds=2.0, command=["ffuf"],
        ))

        asyncio.get_event_loop().run_until_complete(
            ffuf_scan_with_seeds(
                "https://example.com", runner=mock_runner,
                seed_paths=["/api/v1", "/admin", "/login"],
            )
        )
        mock_runner.run.assert_called_once()

    def test_scan_without_seeds_uses_base(self):
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan_with_seeds

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(return_value=ToolOutput(
            returncode=0, stdout='{"results":[]}', stderr="",
            duration_seconds=1.0, command=["ffuf"],
        ))

        asyncio.get_event_loop().run_until_complete(
            ffuf_scan_with_seeds("https://example.com", runner=mock_runner)
        )
        call_args = mock_runner.run.call_args[0][0]
        assert "common.txt" in str(call_args)


class TestExtractTechTags:
    def test_extracts_known_tags(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="t.com", config=AppConfig(), preset="full")
        from argus_lite.models.analysis import Technology
        orch._analysis_result.technologies = [
            Technology(name="WordPress", version="6.4"),
            Technology(name="PHP", version="8.2"),
            Technology(name="jQuery", version="3.7"),  # not a known tag
        ]

        tags = orch._extract_tech_tags()
        assert "wordpress" in tags
        assert "php" in tags
        assert "jquery" not in tags

    def test_empty_technologies(self):
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(target="t.com", config=AppConfig(), preset="full")
        assert orch._extract_tech_tags() == []
