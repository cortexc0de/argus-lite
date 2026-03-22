"""TDD: Tests for TLS certificate scanning via tlsx — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def tlsx_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "tlsx_output.json").read_text()


class TestTlsxParser:
    def test_parse_certs_count(self, tlsx_output):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output(tlsx_output)
        assert len(certs) == 2

    def test_parse_san_entries(self, tlsx_output):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output(tlsx_output)
        main = [c for c in certs if c.host == "example.com:443"][0]
        assert "example.com" in main.san
        assert "www.example.com" in main.san
        assert len(main.san) == 5

    def test_parse_issuer(self, tlsx_output):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output(tlsx_output)
        mail = [c for c in certs if c.host == "mail.example.com:443"][0]
        assert mail.issuer == "Let's Encrypt"

    def test_parse_not_expired(self, tlsx_output):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output(tlsx_output)
        assert all(not c.expired for c in certs)

    def test_parse_not_self_signed(self, tlsx_output):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output(tlsx_output)
        assert all(not c.self_signed for c in certs)

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.tlsx_certs import parse_tlsx_output

        certs = parse_tlsx_output("")
        assert certs == []


class TestTlsxScan:
    def test_scan_with_mock_runner(self, tlsx_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.tlsx_certs import tlsx_scan

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=tlsx_output,
                stderr="",
                duration_seconds=6.0,
                command=["tlsx"],
            )
        )

        import asyncio
        targets = ["example.com:443", "mail.example.com:443"]
        certs = asyncio.get_event_loop().run_until_complete(
            tlsx_scan(targets, runner=mock_runner)
        )
        assert len(certs) == 2
        assert all(hasattr(c, "subject_cn") for c in certs)
