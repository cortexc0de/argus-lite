"""Tests for directory fuzzing via ffuf."""

from pathlib import Path

import pytest


@pytest.fixture
def ffuf_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "ffuf_output.json").read_text()


class TestFfufParser:
    def test_parse_results_count(self, ffuf_output):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output(ffuf_output)
        assert len(results) == 4

    def test_parse_status_codes(self, ffuf_output):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output(ffuf_output)
        statuses = {r.url: r.status_code for r in results}
        assert statuses["https://example.com/admin"] == 200
        assert statuses["https://example.com/.git"] == 403
        assert statuses["https://example.com/wp-login.php"] == 302

    def test_parse_redirect_location(self, ffuf_output):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output(ffuf_output)
        wp_login = [r for r in results if "wp-login" in r.url][0]
        assert wp_login.redirect_location == "https://example.com/wp-admin/"

    def test_parse_content_length(self, ffuf_output):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output(ffuf_output)
        admin = [r for r in results if "admin" in r.url and ".git" not in r.url][0]
        assert admin.content_length == 5432

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output("")
        assert results == []

    def test_parse_invalid_json(self):
        from argus_lite.modules.analysis.ffuf_fuzz import parse_ffuf_output

        results = parse_ffuf_output("{invalid json")
        assert results == []


class TestFfufScan:
    def test_scan_with_mock_runner(self, ffuf_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0,
                stdout=ffuf_output,
                stderr="",
                duration_seconds=15.0,
                command=["ffuf"],
            )
        )

        import asyncio
        results = asyncio.get_event_loop().run_until_complete(
            ffuf_scan("https://example.com", runner=mock_runner,
                      wordlist="/usr/share/wordlists/common.txt")
        )
        assert len(results) == 4
        assert all(hasattr(r, "status_code") for r in results)
