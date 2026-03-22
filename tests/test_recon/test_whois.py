"""TDD: Tests for Whois lookup — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def whois_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "whois_output.txt").read_text()


class TestWhoisParser:
    def test_parse_domain_name(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert info.domain == "example.com"

    def test_parse_registrar(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert "IANA" in info.registrar or "Internet Assigned" in info.registrar

    def test_parse_creation_date(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert "1995" in info.creation_date

    def test_parse_expiration_date(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert "2026" in info.expiration_date

    def test_parse_name_servers(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert len(info.name_servers) == 2
        assert "a.iana-servers.net" in [ns.lower() for ns in info.name_servers]

    def test_parse_raw_preserved(self, whois_output):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output(whois_output)
        assert len(info.raw) > 0

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.whois import parse_whois_output

        info = parse_whois_output("")
        assert info.domain == ""


class TestWhoisLookup:
    def test_whois_lookup_returns_info(self, whois_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.whois import whois_lookup

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=whois_output,
                stderr="",
                duration_seconds=1.0,
                command=["whois"],
            )
        )

        import asyncio
        info = asyncio.get_event_loop().run_until_complete(
            whois_lookup("example.com", runner=mock_runner)
        )
        assert info.domain == "example.com"
        assert len(info.name_servers) == 2
