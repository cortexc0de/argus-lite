"""TDD: Tests for GreyNoise API integration."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_greynoise_response(ip: str = "8.8.8.8") -> dict:
    return {
        "ip": ip,
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": "https://www.shodan.io/host/8.8.8.8",
        "last_seen": "2025-01-15",
        "message": "Success",
    }


class TestParseGreyNoiseResponse:
    def test_parses_ip(self):
        from argus_lite.modules.recon.greynoise_api import parse_greynoise_response
        info = parse_greynoise_response(_make_greynoise_response())
        assert info.ip == "8.8.8.8"

    def test_parses_classification(self):
        from argus_lite.modules.recon.greynoise_api import parse_greynoise_response
        info = parse_greynoise_response(_make_greynoise_response())
        assert info.classification == "benign"
        assert info.riot is True

    def test_parses_noise_false(self):
        from argus_lite.modules.recon.greynoise_api import parse_greynoise_response
        info = parse_greynoise_response(_make_greynoise_response())
        assert info.noise is False

    def test_malicious_ip(self):
        from argus_lite.modules.recon.greynoise_api import parse_greynoise_response
        data = {"ip": "1.2.3.4", "noise": True, "riot": False,
                "classification": "malicious", "name": "Unknown", "last_seen": "", "message": "Success"}
        info = parse_greynoise_response(data)
        assert info.classification == "malicious"
        assert info.noise is True

    def test_empty_response(self):
        from argus_lite.modules.recon.greynoise_api import parse_greynoise_response
        info = parse_greynoise_response({})
        assert info.ip == ""


class TestGreyNoiseLookup:
    def test_lookup_uses_key_header(self):
        from argus_lite.modules.recon.greynoise_api import greynoise_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_greynoise_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                greynoise_lookup("8.8.8.8", api_key="gn-test-key")
            )
            headers = mock_get.call_args.kwargs.get("headers", {})
            assert headers.get("key") == "gn-test-key"

    def test_works_without_key_community_endpoint(self):
        from argus_lite.modules.recon.greynoise_api import greynoise_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_greynoise_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                greynoise_lookup("8.8.8.8", api_key="")
            )
        assert result.ip == "8.8.8.8"

    def test_returns_empty_on_http_error(self):
        from argus_lite.modules.recon.greynoise_api import greynoise_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 429  # rate limit
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                greynoise_lookup("8.8.8.8", api_key="key")
            )
        assert result.ip == ""
