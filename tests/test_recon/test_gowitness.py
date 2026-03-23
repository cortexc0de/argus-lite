"""TDD: Tests for gowitness screenshot capture."""

from pathlib import Path

import pytest


@pytest.fixture
def gowitness_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "gowitness_output.json").read_text()


class TestGoWitnessParser:
    def test_parse_count(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        assert len(screenshots) == 4

    def test_parse_url(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        urls = {s.url for s in screenshots}
        assert "https://example.com" in urls
        assert "https://mail.example.com" in urls

    def test_parse_title(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        main = [s for s in screenshots if s.url == "https://example.com"][0]
        assert main.title == "Example Domain"

    def test_parse_status_code(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        api = [s for s in screenshots if "api" in s.url][0]
        assert api.status_code == 403

    def test_parse_screenshot_path(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        assert all(s.screenshot_path.endswith(".png") for s in screenshots)

    def test_parse_filename(self, gowitness_output):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        screenshots = parse_gowitness_output(gowitness_output)
        main = [s for s in screenshots if s.url == "https://example.com"][0]
        assert main.filename == "example.com.png"

    def test_parse_empty(self):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        assert parse_gowitness_output("") == []

    def test_parse_invalid_json_skipped(self):
        from argus_lite.modules.recon.gowitness import parse_gowitness_output

        bad = 'not json\n{"url":"https://x.com","final_url":"https://x.com/","status_code":200,"title":"X","filename":"x.png","screenshot_path":"/tmp/x.png","response_time_ms":100}\n'
        screenshots = parse_gowitness_output(bad)
        assert len(screenshots) == 1


class TestGoWitnessCapture:
    def test_capture_with_mock(self, gowitness_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.recon.gowitness import gowitness_capture

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0, stdout=gowitness_output, stderr="",
                duration_seconds=15.0, command=["gowitness"],
            )
        )

        import asyncio
        screenshots = asyncio.get_event_loop().run_until_complete(
            gowitness_capture(["https://example.com"], runner=mock_runner,
                              output_dir="/tmp/screenshots")
        )
        assert len(screenshots) == 4
        assert all(hasattr(s, "url") for s in screenshots)
