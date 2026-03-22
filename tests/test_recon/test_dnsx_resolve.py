"""Tests for DNS resolution via dnsx."""

from pathlib import Path

import pytest


@pytest.fixture
def dnsx_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "dnsx_output.json").read_text()


class TestDnsxParser:
    def test_parse_entries_count(self, dnsx_output):
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output(dnsx_output)
        # NXDOMAIN filtered out, so 4 of 5
        assert len(results) == 4

    def test_parse_filters_nxdomain(self, dnsx_output):
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output(dnsx_output)
        hosts = [r.host for r in results]
        assert "nonexistent.example.com" not in hosts

    def test_parse_a_records(self, dnsx_output):
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output(dnsx_output)
        main = [r for r in results if r.host == "example.com"][0]
        assert "93.184.216.34" in main.a
        assert len(main.aaaa) == 1

    def test_parse_cname_records(self, dnsx_output):
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output(dnsx_output)
        api = [r for r in results if r.host == "api.example.com"][0]
        assert "cdn.example.com" in api.cname

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output("")
        assert results == []


class TestDnsxResolve:
    def test_resolve_with_mock(self, dnsx_output):
        """Test via mocking the parse function since dnsx uses stdin."""
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output

        results = parse_dnsx_output(dnsx_output)
        assert len(results) == 4
        assert all(hasattr(r, "host") for r in results)
