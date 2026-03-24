"""TDD: Tests for Threat Intelligence feed."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_nvd_response(cve_id: str = "CVE-2025-0001", score: float = 9.8) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}
                        ]
                    },
                    "references": [{"url": "https://example.com"}],
                }
            }
        ]
    }


class TestFetchRecentCves:
    def test_fetches_with_keyword(self):
        from argus_lite.core.threat_intel import fetch_recent_cves

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response("CVE-2025-1111", 8.0)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            vulns = asyncio.get_event_loop().run_until_complete(
                fetch_recent_cves(["WordPress"], api_key="test")
            )
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2025-1111"

    def test_empty_keywords(self):
        from argus_lite.core.threat_intel import fetch_recent_cves

        vulns = asyncio.get_event_loop().run_until_complete(
            fetch_recent_cves([])
        )
        assert vulns == []

    def test_api_error_returns_empty(self):
        from argus_lite.core.threat_intel import fetch_recent_cves

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            vulns = asyncio.get_event_loop().run_until_complete(
                fetch_recent_cves(["Apache"], api_key="test")
            )
        assert vulns == []


class TestCheckThreatFeed:
    def test_returns_summary(self):
        from argus_lite.core.threat_intel import check_threat_feed

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_nvd_response("CVE-2025-CRIT", 9.5)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                check_threat_feed(["Nginx"], api_key="test", days=7)
            )

        assert result["total_cves"] == 1
        assert result["critical_count"] == 1
        assert result["technologies_checked"] == ["Nginx"]

    def test_separates_critical_from_high(self):
        from argus_lite.core.threat_intel import check_threat_feed

        def mock_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-A", "descriptions": [{"lang": "en", "value": ""}],
                             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}, "references": []}},
                    {"cve": {"id": "CVE-B", "descriptions": [{"lang": "en", "value": ""}],
                             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}, "references": []}},
                ]
            }
            return resp

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            result = asyncio.get_event_loop().run_until_complete(
                check_threat_feed(["PHP"], api_key="test")
            )
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
        assert result["total_cves"] == 2
