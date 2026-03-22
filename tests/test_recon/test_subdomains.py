"""TDD: Tests for subdomain enumeration — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def subfinder_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "subfinder_output.txt").read_text()


class TestSubfinderParser:
    def test_parse_subdomains(self, subfinder_output):
        from argus_lite.modules.recon.subdomains import parse_subfinder_output

        subs = parse_subfinder_output(subfinder_output)
        assert len(subs) == 7

    def test_parse_subdomain_names(self, subfinder_output):
        from argus_lite.modules.recon.subdomains import parse_subfinder_output

        subs = parse_subfinder_output(subfinder_output)
        names = {s.name for s in subs}
        assert "www.example.com" in names
        assert "api.example.com" in names
        assert "mail.example.com" in names

    def test_parse_sets_source(self, subfinder_output):
        from argus_lite.modules.recon.subdomains import parse_subfinder_output

        subs = parse_subfinder_output(subfinder_output, source="subfinder")
        assert all(s.source == "subfinder" for s in subs)

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.subdomains import parse_subfinder_output

        subs = parse_subfinder_output("")
        assert subs == []

    def test_parse_deduplicates(self):
        from argus_lite.modules.recon.subdomains import parse_subfinder_output

        duped = "www.example.com\nwww.example.com\napi.example.com\n"
        subs = parse_subfinder_output(duped)
        assert len(subs) == 2


class TestSubdomainEnumerate:
    def test_enumerate_with_mock_runner(self, subfinder_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.subdomains import subdomain_enumerate

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=subfinder_output,
                stderr="",
                duration_seconds=5.0,
                command=["subfinder"],
            )
        )

        import asyncio
        subs = asyncio.get_event_loop().run_until_complete(
            subdomain_enumerate("example.com", runner=mock_runner)
        )
        assert len(subs) == 7
        assert all(s.source == "subfinder" for s in subs)
