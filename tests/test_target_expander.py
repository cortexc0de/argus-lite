"""TDD: Tests for TargetExpander — written BEFORE implementation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def config():
    from argus_lite.core.config import AppConfig
    return AppConfig()


@pytest.fixture
def expander(config):
    from argus_lite.core.target_expander import TargetExpander
    return TargetExpander(config)


class TestDetectSourceType:
    def test_detects_existing_file(self, tmp_path, expander):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n")
        assert expander._detect_source_type(str(f)) == "file"

    def test_detects_cidr_ipv4(self, expander):
        assert expander._detect_source_type("192.168.1.0/24") == "cidr"
        assert expander._detect_source_type("10.0.0.0/8") == "cidr"

    def test_detects_asn(self, expander):
        assert expander._detect_source_type("AS12345") == "asn"
        assert expander._detect_source_type("as6789") == "asn"

    def test_detects_plain_host(self, expander):
        assert expander._detect_source_type("example.com") == "host"
        assert expander._detect_source_type("192.168.1.1") == "host"

    def test_detects_unknown_as_shodan(self, expander):
        assert expander._detect_source_type("org:MyCompany port:443") == "shodan"


class TestExpandFile:
    def test_reads_lines(self, tmp_path, expander):
        f = tmp_path / "t.txt"
        f.write_text("example.com\ngoogle.com\n")
        result = expander._expand_file(str(f))
        assert "example.com" in result
        assert "google.com" in result

    def test_skips_comments_and_blanks(self, tmp_path, expander):
        f = tmp_path / "t.txt"
        f.write_text("# comment\nexample.com\n\n  # another\ngoogle.com\n")
        result = expander._expand_file(str(f))
        assert len(result) == 2
        assert "example.com" in result

    def test_strips_whitespace(self, tmp_path, expander):
        f = tmp_path / "t.txt"
        f.write_text("  example.com  \n  google.com  \n")
        result = expander._expand_file(str(f))
        assert "example.com" in result

    def test_nonexistent_file_raises(self, expander):
        with pytest.raises(FileNotFoundError):
            expander._expand_file("/nonexistent/targets.txt")


class TestExpandCidr:
    def test_expands_small_range(self, expander):
        result = expander._expand_cidr("192.168.1.0/30")
        # /30 = 4 IPs (2 usable + network + broadcast), but we skip network/broadcast
        assert len(result) >= 2
        assert all("192.168.1." in ip for ip in result)

    def test_hard_cap_on_large_cidr(self, expander):
        # /16 = 65536 IPs, should be capped at hard safety limit (65536)
        # but NOT at max_targets — that cap is applied in expand()
        result = expander._expand_cidr("10.0.0.0/16")
        assert len(result) <= 65536
        assert len(result) > 50  # definitely more than the old max_targets=50

    def test_single_host_cidr(self, expander):
        result = expander._expand_cidr("192.168.1.1/32")
        assert len(result) == 1
        assert result[0] == "192.168.1.1"

    def test_invalid_cidr_raises(self, expander):
        with pytest.raises(ValueError):
            expander._expand_cidr("999.999.999.999/24")


class TestExpandAsn:
    def test_expands_asn_via_api(self, expander):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipv4_prefixes": [
                    {"prefix": "192.168.1.0/30"},
                    {"prefix": "10.0.0.0/30"},
                ]
            }
        }
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                expander._expand_asn("AS12345")
            )
        assert len(result) > 0

    def test_asn_api_error_returns_empty(self, expander):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                expander._expand_asn("AS99999")
            )
        assert result == []


class TestExpandIntegration:
    def test_expand_plain_host(self, expander):
        result = asyncio.get_event_loop().run_until_complete(
            expander.expand(["example.com"])
        )
        assert "example.com" in result

    def test_expand_deduplicates(self, tmp_path, expander):
        f = tmp_path / "t.txt"
        f.write_text("example.com\nexample.com\n")
        result = asyncio.get_event_loop().run_until_complete(
            expander.expand([str(f), "example.com"])
        )
        assert result.count("example.com") == 1

    def test_expand_caps_total_at_max_targets(self, expander):
        # expand() applies max_targets cap; default is 500
        result = asyncio.get_event_loop().run_until_complete(
            expander.expand(["10.0.0.0/16"])
        )
        assert len(result) <= expander._max_targets
        # For a /16 (65536 IPs) capped at 500
        assert len(result) == expander._max_targets
