"""TDD: Tests for tech stack fingerprinting — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def whatweb_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "whatweb_output.json").read_text()


class TestWhatwebParser:
    def test_parse_technologies(self, whatweb_output):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output(whatweb_output)
        assert len(techs) >= 5

    def test_parse_wordpress_version(self, whatweb_output):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output(whatweb_output)
        wp = [t for t in techs if t.name == "WordPress"]
        assert len(wp) == 1
        assert wp[0].version == "6.4.2"

    def test_parse_jquery_version(self, whatweb_output):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output(whatweb_output)
        jq = [t for t in techs if t.name == "jQuery"]
        assert len(jq) == 1
        assert jq[0].version == "3.7.1"

    def test_parse_no_version_technology(self, whatweb_output):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output(whatweb_output)
        html5 = [t for t in techs if t.name == "HTML5"]
        assert len(html5) == 1
        assert html5[0].version == ""

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output("")
        assert techs == []

    def test_parse_invalid_json(self):
        from argus_lite.modules.analysis.techstack import parse_whatweb_output

        techs = parse_whatweb_output("not json at all")
        assert techs == []

    def test_tech_scan_with_mock(self, whatweb_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.analysis.techstack import tech_scan

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0, stdout=whatweb_output, stderr="",
                duration_seconds=3.0, command=["whatweb"],
            )
        )

        import asyncio
        techs = asyncio.get_event_loop().run_until_complete(
            tech_scan("example.com", runner=mock_runner)
        )
        assert len(techs) >= 5
