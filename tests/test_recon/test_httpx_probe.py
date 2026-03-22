"""TDD: Tests for HTTP probing via httpx — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def httpx_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "httpx_output.json").read_text()


class TestHttpxParser:
    def test_parse_probes_count(self, httpx_output):
        from argus_lite.modules.recon.httpx_probe import parse_httpx_output

        probes = parse_httpx_output(httpx_output)
        assert len(probes) == 4

    def test_parse_status_codes(self, httpx_output):
        from argus_lite.modules.recon.httpx_probe import parse_httpx_output

        probes = parse_httpx_output(httpx_output)
        codes = {p.url: p.status_code for p in probes}
        assert codes["https://example.com"] == 200
        assert codes["https://www.example.com"] == 301
        assert codes["https://api.example.com"] == 403

    def test_parse_tech_list(self, httpx_output):
        from argus_lite.modules.recon.httpx_probe import parse_httpx_output

        probes = parse_httpx_output(httpx_output)
        main = [p for p in probes if p.url == "https://example.com"][0]
        assert "Apache" in main.tech
        assert "PHP" in main.tech
        assert "jQuery" in main.tech

    def test_parse_server(self, httpx_output):
        from argus_lite.modules.recon.httpx_probe import parse_httpx_output

        probes = parse_httpx_output(httpx_output)
        mail = [p for p in probes if p.url == "https://mail.example.com"][0]
        assert mail.server == "nginx"

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.httpx_probe import parse_httpx_output

        probes = parse_httpx_output("")
        assert probes == []


class TestHttpxProbe:
    def test_probe_with_mock_runner(self, httpx_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.httpx_probe import httpx_probe

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=httpx_output,
                stderr="",
                duration_seconds=3.0,
                command=["httpx"],
            )
        )

        import asyncio
        probes = asyncio.get_event_loop().run_until_complete(
            httpx_probe("example.com", runner=mock_runner)
        )
        assert len(probes) == 4
        assert all(hasattr(p, "status_code") for p in probes)
