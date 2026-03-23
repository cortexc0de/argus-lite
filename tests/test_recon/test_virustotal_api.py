"""TDD: Tests for VirusTotal API integration — written BEFORE implementation."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def vt_raw(fixtures_dir: Path) -> str:
    return (fixtures_dir / "virustotal_domain.json").read_text()


class TestParseVtResponse:
    def test_parse_domain(self, vt_raw):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response(vt_raw)
        assert info.domain == "example.com"

    def test_parse_reputation(self, vt_raw):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response(vt_raw)
        assert info.reputation == 0

    def test_parse_analysis_stats(self, vt_raw):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response(vt_raw)
        assert info.malicious_count == 0
        assert info.harmless_count == 70

    def test_parse_dns_records(self, vt_raw):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response(vt_raw)
        assert len(info.dns_records) == 3

    def test_parse_certificate(self, vt_raw):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response(vt_raw)
        assert "example.org" in info.certificate_subject

    def test_parse_empty(self):
        from argus_lite.modules.recon.virustotal_api import parse_vt_response

        info = parse_vt_response("")
        assert info.domain == ""
        assert info.reputation == 0
        assert info.malicious_count == 0
        assert info.dns_records == []

    def test_lookup_with_mock(self):
        from argus_lite.modules.recon.virustotal_api import vt_lookup

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"data": {"id": "test.com", "type": "domain", "attributes": {"last_analysis_stats": {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0}, "reputation": 0, "last_dns_records": [], "last_https_certificate": {"subject": {"CN": ""}, "issuer": {"O": ""}}}}}'

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response) as mock_get:
            result = asyncio.get_event_loop().run_until_complete(
                vt_lookup("test.com", api_key="VT_TEST_KEY")
            )
            call_kwargs = mock_get.call_args
            # Verify the x-apikey header is passed
            headers = call_kwargs.kwargs.get("headers", {}) if call_kwargs.kwargs else {}
            assert headers.get("x-apikey") == "VT_TEST_KEY"
