"""TDD: Tests for Censys API integration."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_censys_response(ip: str = "93.184.216.34") -> dict:
    return {
        "result": {
            "ip": ip,
            "labels": ["cloud"],
            "last_updated_at": "2025-01-15T12:00:00Z",
            "services": [
                {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS",
                 "banner": "HTTP/1.1 200 OK"},
                {"port": 80, "transport_protocol": "TCP", "service_name": "HTTP",
                 "banner": "HTTP/1.1 301"},
            ],
        }
    }


def _make_censys_search_response() -> dict:
    return {
        "result": {
            "total": 2,
            "hits": [
                {"ip": "93.184.216.34"},
                {"ip": "93.184.216.35"},
            ],
        }
    }


class TestParseCensysResponse:
    def test_parses_ip(self):
        from argus_lite.modules.recon.censys_api import parse_censys_host_response
        info = parse_censys_host_response(_make_censys_response())
        assert info.ip == "93.184.216.34"

    def test_parses_services(self):
        from argus_lite.modules.recon.censys_api import parse_censys_host_response
        info = parse_censys_host_response(_make_censys_response())
        assert len(info.services) == 2
        assert any(s.port == 443 for s in info.services)

    def test_parses_labels(self):
        from argus_lite.modules.recon.censys_api import parse_censys_host_response
        info = parse_censys_host_response(_make_censys_response())
        assert "cloud" in info.labels

    def test_empty_response_returns_default(self):
        from argus_lite.modules.recon.censys_api import parse_censys_host_response
        info = parse_censys_host_response({})
        assert info.ip == ""
        assert info.services == []

    def test_parses_search_results(self):
        from argus_lite.modules.recon.censys_api import parse_censys_search_response
        ips = parse_censys_search_response(_make_censys_search_response())
        assert "93.184.216.34" in ips
        assert len(ips) == 2


class TestCensysLookup:
    def test_lookup_with_valid_key(self):
        from argus_lite.modules.recon.censys_api import censys_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_censys_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                censys_lookup("example.com", api_id="test-id", api_secret="test-secret")
            )
        assert result.ip == "93.184.216.34"

    def test_returns_empty_without_key(self):
        from argus_lite.modules.recon.censys_api import censys_lookup
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                censys_lookup("example.com", api_id="", api_secret="")
            )
        mock_get.assert_not_called()
        assert result.ip == ""

    def test_returns_empty_on_error(self):
        from argus_lite.modules.recon.censys_api import censys_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                censys_lookup("example.com", api_id="bad", api_secret="bad")
            )
        assert result.ip == ""


class TestCensysSearch:
    def test_search_returns_ip_list(self):
        from argus_lite.modules.recon.censys_api import censys_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_censys_search_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                censys_search("services.port:443", api_id="id", api_secret="secret")
            )
        assert len(result) == 2

    def test_search_returns_empty_without_key(self):
        from argus_lite.modules.recon.censys_api import censys_search
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                censys_search("services.port:443", api_id="", api_secret="")
            )
        mock_get.assert_not_called()
        assert result == []
