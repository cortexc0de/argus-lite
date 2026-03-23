"""TDD: Tests for Shodan API integration — written BEFORE implementation."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def shodan_raw(fixtures_dir: Path) -> str:
    return (fixtures_dir / "shodan_host.json").read_text()


class TestParseShodanResponse:
    def test_parse_ip(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert info.ip == "93.184.216.34"

    def test_parse_hostnames(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert "example.com" in info.hostnames

    def test_parse_org(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert "Edgecast" in info.org

    def test_parse_ports(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert info.ports == [80, 443]

    def test_parse_country(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert info.country == "US"

    def test_parse_services(self, shodan_raw):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response(shodan_raw)
        assert len(info.services) == 2

    def test_parse_empty(self):
        from argus_lite.modules.recon.shodan_api import parse_shodan_response

        info = parse_shodan_response("")
        assert info.ip == ""
        assert info.hostnames == []
        assert info.ports == []
        assert info.services == []

    def test_lookup_with_mock(self):
        from argus_lite.modules.recon.shodan_api import shodan_lookup

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"ip_str": "1.2.3.4", "hostnames": [], "org": "", "ports": [], "vulns": [], "data": [], "country_code": "", "city": "", "isp": ""}'

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                shodan_lookup("1.2.3.4", api_key="TEST_KEY")
            )
            call_url = mock_get.call_args[0][0] if mock_get.call_args[0] else str(mock_get.call_args)
            assert "TEST_KEY" in call_url
