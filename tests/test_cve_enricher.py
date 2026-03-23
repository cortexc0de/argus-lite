"""TDD: Tests for CVE enricher (NVD API v2.0) — written BEFORE implementation."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_nvd_response(cve_id: str = "CVE-2023-1234", score: float = 7.5) -> dict:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }
        ],
    }


def _make_nvd_response_v30(cve_id: str = "CVE-2023-5678", score: float = 5.0) -> dict:
    """Response with only CVSS v3.0 (no v3.1)."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV30": [{"cvssData": {"baseScore": score, "vectorString": "CVSS:3.0/AV:N"}}]
                    },
                    "references": [],
                }
            }
        ],
    }


def _make_nvd_response_v2(cve_id: str = "CVE-2023-9999", score: float = 4.3) -> dict:
    """Response with only CVSS v2 (no v3.x)."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV2": [{"cvssData": {"baseScore": score, "vectorString": "AV:N/AC:M"}}]
                    },
                    "references": [],
                }
            }
        ],
    }


def _make_technology(name: str, version: str = "") -> object:
    from argus_lite.models.analysis import Technology

    return Technology(name=name, version=version)


class TestCveEnricherEnrich:
    def test_enriches_tech_with_version(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response("CVE-2023-1234", 7.5)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            tech = _make_technology("WordPress", "6.3.1")
            result = asyncio.get_event_loop().run_until_complete(enricher.enrich([tech]))

        assert len(result) == 1
        assert result[0].cve == "CVE-2023-1234"
        assert result[0].cvss_score == 7.5

    def test_skips_tech_without_version(self):
        from argus_lite.core.cve_enricher import CveEnricher

        enricher = CveEnricher()
        tech = _make_technology("Apache", "")  # no version
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(enricher.enrich([tech]))
        mock_get.assert_not_called()
        assert result == []

    def test_empty_technology_list(self):
        from argus_lite.core.cve_enricher import CveEnricher

        enricher = CveEnricher()
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(enricher.enrich([]))
        mock_get.assert_not_called()
        assert result == []

    def test_multiple_techs_with_version(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response("CVE-2023-XXXX", 5.0)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            techs = [
                _make_technology("WordPress", "6.3.1"),
                _make_technology("Apache", "2.4.51"),
                _make_technology("Nginx", ""),  # skipped
            ]
            result = asyncio.get_event_loop().run_until_complete(enricher.enrich(techs))

        # 2 techs with version → 2 queries × 1 result each = 2 vulnerabilities
        assert len(result) == 2


class TestCvssVersionParsing:
    def test_parses_cvss_v31(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response("CVE-2023-1111", 9.8)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("PHP", "8.0.0")])
            )

        assert result[0].cvss_score == 9.8
        assert result[0].cvss_vector is not None
        assert "CVSS:3.1" in (result[0].cvss_vector or "")

    def test_parses_cvss_v30_fallback(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response_v30("CVE-2023-2222", 5.0)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("Joomla", "3.9.0")])
            )

        assert result[0].cvss_score == 5.0

    def test_parses_cvss_v2_fallback(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response_v2("CVE-2023-3333", 4.3)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("OpenSSL", "1.0.2")])
            )

        assert result[0].cvss_score == 4.3


class TestCveEnricherErrorHandling:
    def test_returns_empty_on_http_error(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("Drupal", "9.0.0")])
            )

        assert result == []

    def test_returns_empty_on_timeout(self):
        import httpx

        from argus_lite.core.cve_enricher import CveEnricher

        with patch(
            "httpx.AsyncClient.get",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("timeout"),
        ):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("Laravel", "8.0")])
            )

        assert result == []

    def test_returns_empty_on_invalid_json(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("not json")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            enricher = CveEnricher()
            result = asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("Django", "4.0.0")])
            )

        assert result == []


class TestCveEnricherApiKey:
    def test_api_key_set_in_header(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            enricher = CveEnricher(api_key="test-nvd-key")
            asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("WordPress", "6.0")])
            )
            call_kwargs = mock_get.call_args.kwargs if mock_get.call_args.kwargs else {}
            headers = call_kwargs.get("headers", {})
            assert headers.get("apiKey") == "test-nvd-key"

    def test_no_key_no_header(self):
        from argus_lite.core.cve_enricher import CveEnricher

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            enricher = CveEnricher(api_key="")
            asyncio.get_event_loop().run_until_complete(
                enricher.enrich([_make_technology("WordPress", "6.0")])
            )
            call_kwargs = mock_get.call_args.kwargs if mock_get.call_args.kwargs else {}
            headers = call_kwargs.get("headers", {})
            assert "apiKey" not in headers
