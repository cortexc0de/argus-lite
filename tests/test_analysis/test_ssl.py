"""TDD: Tests for SSL/TLS check — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def ssl_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "ssl_check_output.txt").read_text()


class TestSSLParser:
    def test_parse_protocol(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert info.protocol == "TLSv1.3"

    def test_parse_cipher(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert "TLS_AES_256_GCM_SHA384" in info.cipher

    def test_parse_issuer(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert "DigiCert" in info.issuer

    def test_parse_subject(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert "example.org" in info.subject

    def test_parse_validity(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert "2026" in info.not_before
        assert "2027" in info.not_after

    def test_not_expired(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert info.expired is False

    def test_not_weak_cipher(self, ssl_output):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output(ssl_output)
        assert info.weak_cipher is False

    def test_detect_weak_cipher(self):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        weak = "New, TLSv1.0, Cipher is RC4-SHA\nVerify return code: 0 (ok)\n"
        info = parse_ssl_output(weak)
        assert info.weak_cipher is True
        assert info.protocol == "TLSv1.0"

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.ssl import parse_ssl_output

        info = parse_ssl_output("")
        assert info.protocol == ""
        assert info.cipher == ""

    def test_ssl_check_with_mock(self, ssl_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.analysis.ssl import ssl_check

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0, stdout=ssl_output, stderr="",
                duration_seconds=2.0, command=["openssl"],
            )
        )

        import asyncio
        info = asyncio.get_event_loop().run_until_complete(
            ssl_check("example.com", runner=mock_runner)
        )
        assert info.protocol == "TLSv1.3"
