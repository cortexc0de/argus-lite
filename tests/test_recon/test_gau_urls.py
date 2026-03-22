"""TDD: Tests for historical URL discovery via gau — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def gau_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "gau_output.txt").read_text()


class TestGauParser:
    def test_parse_urls_count(self, gau_output):
        from argus_lite.modules.recon.gau_urls import parse_gau_output

        results = parse_gau_output(gau_output)
        assert len(results) == 7

    def test_parse_source_is_gau(self, gau_output):
        from argus_lite.modules.recon.gau_urls import parse_gau_output

        results = parse_gau_output(gau_output)
        assert all(r.source == "gau" for r in results)

    def test_parse_url_values(self, gau_output):
        from argus_lite.modules.recon.gau_urls import parse_gau_output

        results = parse_gau_output(gau_output)
        urls = {r.url for r in results}
        assert "https://example.com/.env" in urls
        assert "https://example.com/backup.sql" in urls

    def test_parse_deduplicates(self):
        from argus_lite.modules.recon.gau_urls import parse_gau_output

        duped = "https://example.com/a\nhttps://example.com/a\nhttps://example.com/b\n"
        results = parse_gau_output(duped)
        assert len(results) == 2

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.gau_urls import parse_gau_output

        results = parse_gau_output("")
        assert results == []


class TestGauDiscover:
    def test_discover_with_mock_runner(self, gau_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.gau_urls import gau_discover

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=gau_output,
                stderr="",
                duration_seconds=12.0,
                command=["gau"],
            )
        )

        import asyncio
        results = asyncio.get_event_loop().run_until_complete(
            gau_discover("example.com", runner=mock_runner)
        )
        assert len(results) == 7
        assert all(r.source == "gau" for r in results)
