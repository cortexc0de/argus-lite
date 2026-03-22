"""TDD: Tests for DNS enumeration — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def dig_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "dig_output.txt").read_text()


class TestDigParser:
    def test_parse_a_record(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        a_records = [r for r in records if r.type == "A"]
        assert len(a_records) == 1
        assert a_records[0].value == "93.184.216.34"
        assert a_records[0].name == "example.com"
        assert a_records[0].ttl == 300

    def test_parse_aaaa_record(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        aaaa = [r for r in records if r.type == "AAAA"]
        assert len(aaaa) == 1
        assert "2606:2800" in aaaa[0].value

    def test_parse_mx_record(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        mx = [r for r in records if r.type == "MX"]
        assert len(mx) == 1
        assert "mail.example.com" in mx[0].value

    def test_parse_ns_records(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        ns = [r for r in records if r.type == "NS"]
        assert len(ns) == 2

    def test_parse_txt_record(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        txt = [r for r in records if r.type == "TXT"]
        assert len(txt) == 1
        assert "spf1" in txt[0].value

    def test_parse_cname_record(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        cname = [r for r in records if r.type == "CNAME"]
        assert len(cname) == 1
        assert cname[0].value == "www.example.com"

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output("")
        assert records == []

    def test_parse_skips_soa(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        types = {r.type for r in records}
        assert "SOA" not in types

    def test_total_record_count(self, dig_output):
        from argus_lite.modules.recon.dns import parse_dig_output

        records = parse_dig_output(dig_output)
        # A, AAAA, MX, NS*2, TXT, CNAME = 7 (SOA skipped)
        assert len(records) == 7


class TestDnsEnumerate:
    """Test the high-level dns_enumerate function."""

    def test_dns_enumerate_returns_recon_result(self, dig_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.dns import dns_enumerate

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=dig_output,
                stderr="",
                duration_seconds=0.5,
                command=["dig"],
            )
        )

        import asyncio
        records = asyncio.get_event_loop().run_until_complete(
            dns_enumerate("example.com", runner=mock_runner)
        )
        assert len(records) == 7
        assert all(r.name == "example.com" for r in records)
