"""TDD: Tests for FOFA API integration."""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_fofa_response() -> dict:
    return {
        "error": False,
        "query": "domain=\"example.com\"",
        "size": 2,
        "page": 1,
        "mode": "extended",
        "results": [
            ["93.184.216.34", "443", "https", "US", "Ashburn", "Apache"],
            ["93.184.216.34", "80", "http", "US", "Ashburn", "Apache"],
        ],
    }


class TestParseFofaResponse:
    def test_parses_total(self):
        from argus_lite.modules.recon.fofa_api import parse_fofa_response
        info = parse_fofa_response(_make_fofa_response())
        assert info.total == 2

    def test_parses_results(self):
        from argus_lite.modules.recon.fofa_api import parse_fofa_response
        info = parse_fofa_response(_make_fofa_response())
        assert len(info.results) == 2

    def test_result_has_expected_fields(self):
        from argus_lite.modules.recon.fofa_api import parse_fofa_response
        info = parse_fofa_response(_make_fofa_response())
        assert info.results[0]["ip"] == "93.184.216.34"
        assert info.results[0]["port"] == "443"

    def test_error_response_returns_empty(self):
        from argus_lite.modules.recon.fofa_api import parse_fofa_response
        info = parse_fofa_response({"error": True, "errmsg": "Auth failed"})
        assert info.total == 0


class TestFofaLookup:
    def test_lookup_uses_base64_query(self):
        from argus_lite.modules.recon.fofa_api import fofa_lookup

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_fofa_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                fofa_lookup("example.com", email="test@test.com", api_key="testkey")
            )
            call_params = mock_get.call_args.kwargs.get("params", {})
            # Verify qbase64 is present and properly encoded
            assert "qbase64" in call_params
            decoded = base64.b64decode(call_params["qbase64"]).decode()
            assert "example.com" in decoded

    def test_returns_empty_without_key(self):
        from argus_lite.modules.recon.fofa_api import fofa_lookup
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                fofa_lookup("example.com", email="", api_key="")
            )
        mock_get.assert_not_called()
        assert result.total == 0

    def test_returns_empty_on_error(self):
        from argus_lite.modules.recon.fofa_api import fofa_lookup
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": True, "errmsg": "not auth"}
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                fofa_lookup("example.com", email="e@e.com", api_key="key")
            )
        assert result.total == 0


class TestFofaSearch:
    def test_search_extracts_ips(self):
        from argus_lite.modules.recon.fofa_api import fofa_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_fofa_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            ips = asyncio.get_event_loop().run_until_complete(
                fofa_search('domain="example.com"', email="e@e.com", api_key="key")
            )
        assert "93.184.216.34" in ips
