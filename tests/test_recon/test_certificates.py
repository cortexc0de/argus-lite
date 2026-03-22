"""TDD: Tests for certificate info — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def openssl_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "openssl_output.txt").read_text()


class TestCertificateParser:
    def test_parse_subject(self, openssl_output):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output(openssl_output)
        assert "www.example.org" in info.subject

    def test_parse_issuer(self, openssl_output):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output(openssl_output)
        assert "DigiCert" in info.issuer

    def test_parse_validity_dates(self, openssl_output):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output(openssl_output)
        assert "2026" in info.not_before
        assert "2027" in info.not_after

    def test_parse_san(self, openssl_output):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output(openssl_output)
        assert len(info.san) >= 4
        assert "www.example.org" in info.san
        assert "example.com" in info.san
        assert "www.example.com" in info.san

    def test_parse_serial(self, openssl_output):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output(openssl_output)
        assert len(info.serial_number) > 0

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        info = parse_openssl_output("")
        assert info.subject == ""
        assert info.san == []

    def test_parse_no_san(self):
        from argus_lite.modules.recon.certificates import parse_openssl_output

        minimal = """Certificate:
    Data:
        Issuer: CN = TestCA
        Subject: CN = test.local
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Dec 31 23:59:59 2026 GMT
"""
        info = parse_openssl_output(minimal)
        assert info.subject == "CN = test.local"
        assert info.issuer == "CN = TestCA"
        assert info.san == []


class TestCertificateInfo:
    def test_certificate_info_with_mock(self, openssl_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.certificates import certificate_info

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=openssl_output,
                stderr="",
                duration_seconds=2.0,
                command=["openssl"],
            )
        )

        import asyncio
        info = asyncio.get_event_loop().run_until_complete(
            certificate_info("example.com", runner=mock_runner)
        )
        assert "www.example.org" in info.subject
        assert len(info.san) >= 4
