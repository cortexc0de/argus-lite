"""TDD: Tests for web headers analysis — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def secure_headers(fixtures_dir: Path) -> str:
    return (fixtures_dir / "curl_headers_output.txt").read_text()


@pytest.fixture
def insecure_headers(fixtures_dir: Path) -> str:
    return (fixtures_dir / "curl_headers_insecure.txt").read_text()


class TestHeaderParser:
    def test_parse_headers_dict(self, secure_headers):
        from argus_lite.modules.analysis.headers import parse_curl_headers

        headers = parse_curl_headers(secure_headers)
        assert headers["server"] == "ECAcc (dcd/7D5A)"
        assert headers["content-type"] == "text/html; charset=UTF-8"

    def test_parse_status_code(self, secure_headers):
        from argus_lite.modules.analysis.headers import parse_curl_headers

        headers = parse_curl_headers(secure_headers)
        assert headers["_status_code"] == 200

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.headers import parse_curl_headers

        headers = parse_curl_headers("")
        assert headers == {}


class TestSecurityHeadersAnalysis:
    def test_secure_site(self, secure_headers):
        from argus_lite.modules.analysis.security_headers import analyze_security_headers

        result = analyze_security_headers(secure_headers)
        assert result.hsts is True
        assert result.x_frame_options is True
        assert result.x_content_type_options is True
        assert result.csp is True
        assert result.referrer_policy is True
        assert result.permissions_policy is True
        # x-xss-protection not in fixture (deprecated header)
        assert result.missing_headers == ["x-xss-protection"]

    def test_insecure_site(self, insecure_headers):
        from argus_lite.modules.analysis.security_headers import analyze_security_headers

        result = analyze_security_headers(insecure_headers)
        assert result.hsts is False
        assert result.x_frame_options is False
        assert result.x_content_type_options is False
        assert result.csp is False
        assert len(result.missing_headers) >= 4

    def test_missing_headers_list(self, insecure_headers):
        from argus_lite.modules.analysis.security_headers import analyze_security_headers

        result = analyze_security_headers(insecure_headers)
        missing_lower = [h.lower() for h in result.missing_headers]
        assert "strict-transport-security" in missing_lower
        assert "x-frame-options" in missing_lower
        assert "content-security-policy" in missing_lower

    def test_empty_input(self):
        from argus_lite.modules.analysis.security_headers import analyze_security_headers

        result = analyze_security_headers("")
        assert result.hsts is False
        assert len(result.missing_headers) >= 4

    def test_generates_findings(self, insecure_headers):
        from argus_lite.modules.analysis.security_headers import security_headers_findings

        findings = security_headers_findings(insecure_headers, asset="test.com")
        assert len(findings) >= 4
        assert all(f.severity in ("INFO", "LOW") for f in findings)
        assert all(f.source == "security_headers" for f in findings)
        assert all(f.asset == "test.com" for f in findings)
