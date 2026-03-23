"""TDD: Tests for ZoomEye API integration."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_zoomeye_response() -> dict:
    return {
        "total": 3,
        "matches": [
            {"ip": "1.1.1.1", "portinfo": {"port": 443, "service": "https"},
             "geoinfo": {"country": {"names": {"en": "United States"}}, "city": {"names": {"en": "San Jose"}}}},
            {"ip": "1.1.1.2", "portinfo": {"port": 80, "service": "http"},
             "geoinfo": {"country": {"names": {"en": "United States"}}, "city": {"names": {"en": "San Jose"}}}},
        ],
    }


class TestParseZoomEyeResponse:
    def test_parses_total(self):
        from argus_lite.modules.recon.zoomeye_api import parse_zoomeye_response
        info = parse_zoomeye_response(_make_zoomeye_response())
        assert info.total == 3

    def test_parses_matches(self):
        from argus_lite.modules.recon.zoomeye_api import parse_zoomeye_response
        info = parse_zoomeye_response(_make_zoomeye_response())
        assert len(info.matches) == 2

    def test_empty_response(self):
        from argus_lite.modules.recon.zoomeye_api import parse_zoomeye_response
        info = parse_zoomeye_response({})
        assert info.total == 0
        assert info.matches == []


class TestZoomEyeLookup:
    def test_lookup_uses_jwt_auth(self):
        from argus_lite.modules.recon.zoomeye_api import zoomeye_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_zoomeye_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                zoomeye_lookup("example.com", api_key="test-key")
            )
            headers = mock_get.call_args.kwargs.get("headers", {})
            assert "Authorization" in headers
            assert "test-key" in headers["Authorization"]

    def test_returns_empty_without_key(self):
        from argus_lite.modules.recon.zoomeye_api import zoomeye_lookup
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                zoomeye_lookup("example.com", api_key="")
            )
        mock_get.assert_not_called()
        assert result.total == 0

    def test_returns_empty_on_http_error(self):
        from argus_lite.modules.recon.zoomeye_api import zoomeye_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                zoomeye_lookup("example.com", api_key="key")
            )
        assert result.total == 0


class TestZoomEyeSearch:
    def test_search_extracts_ips(self):
        from argus_lite.modules.recon.zoomeye_api import zoomeye_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_zoomeye_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            ips = asyncio.get_event_loop().run_until_complete(
                zoomeye_search("hostname:example.com", api_key="key")
            )
        assert "1.1.1.1" in ips
        assert "1.1.1.2" in ips
