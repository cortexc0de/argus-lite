"""TDD: Tests for SecurityTrails API integration — written BEFORE implementation."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def st_raw(fixtures_dir: Path) -> str:
    return (fixtures_dir / "securitytrails_domain.json").read_text()


class TestParseStResponse:
    def test_parse_hostname(self, st_raw):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response(st_raw)
        assert info.hostname == "example.com"

    def test_parse_a_records(self, st_raw):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response(st_raw)
        assert "93.184.216.34" in info.a_records

    def test_parse_mx(self, st_raw):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response(st_raw)
        assert "mail.example.com" in info.mx_records

    def test_parse_ns(self, st_raw):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response(st_raw)
        assert "a.iana-servers.net" in info.ns_records

    def test_parse_subdomain_count(self, st_raw):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response(st_raw)
        assert info.subdomain_count == 25

    def test_parse_empty(self):
        from argus_lite.modules.recon.securitytrails_api import parse_st_response

        info = parse_st_response("")
        assert info.hostname == ""
        assert info.a_records == []
        assert info.mx_records == []
        assert info.ns_records == []
        assert info.subdomain_count == 0

    def test_lookup_with_mock(self):
        from argus_lite.modules.recon.securitytrails_api import st_lookup

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"hostname": "test.com", "current_dns": {"a": {"values": []}, "mx": {"values": []}, "ns": {"values": []}}, "subdomain_count": 0}'

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                st_lookup("test.com", api_key="ST_TEST_KEY")
            )
            call_kwargs = mock_get.call_args
            # Verify the apikey header is passed
            headers = call_kwargs.kwargs.get("headers", {}) if call_kwargs.kwargs else {}
            assert headers.get("APIKEY") == "ST_TEST_KEY"
