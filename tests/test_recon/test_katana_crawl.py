"""TDD: Tests for URL crawling via katana — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def katana_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "katana_output.txt").read_text()


class TestKatanaParser:
    def test_parse_urls_count(self, katana_output):
        from argus_lite.modules.recon.katana_crawl import parse_katana_output

        results = parse_katana_output(katana_output)
        assert len(results) == 10

    def test_parse_url_values(self, katana_output):
        from argus_lite.modules.recon.katana_crawl import parse_katana_output

        results = parse_katana_output(katana_output)
        urls = {r.url for r in results}
        assert "https://example.com/login" in urls
        assert "https://example.com/robots.txt" in urls

    def test_parse_deduplicates(self):
        from argus_lite.modules.recon.katana_crawl import parse_katana_output

        duped = "https://example.com/a\nhttps://example.com/a\nhttps://example.com/b\n"
        results = parse_katana_output(duped)
        assert len(results) == 2

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.katana_crawl import parse_katana_output

        results = parse_katana_output("")
        assert results == []


class TestKatanaCrawl:
    def test_crawl_with_mock_runner(self, katana_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.katana_crawl import katana_crawl

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=katana_output,
                stderr="",
                duration_seconds=8.0,
                command=["katana"],
            )
        )

        import asyncio
        results = asyncio.get_event_loop().run_until_complete(
            katana_crawl("example.com", runner=mock_runner)
        )
        assert len(results) == 10
        assert all(hasattr(r, "url") for r in results)
