"""TDD: Tests for nuclei integration — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def nuclei_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "nuclei_output.json").read_text()


class TestNucleiParser:
    def test_parse_findings_count(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        assert len(findings) == 4

    def test_parse_finding_fields(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        tech = [f for f in findings if f.template_id == "tech-detect"]
        assert len(tech) == 1
        assert tech[0].name == "Technology Detection"
        assert tech[0].severity == "info"

    def test_parse_low_severity(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        low = [f for f in findings if f.severity == "low"]
        assert len(low) == 1
        assert low[0].template_id == "outdated-wordpress"

    def test_parse_matched_at(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        wp = [f for f in findings if f.template_id == "outdated-wordpress"]
        assert "wp-login.php" in wp[0].matched_at

    def test_parse_tags(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        hsts = [f for f in findings if f.template_id == "missing-hsts"]
        assert "headers" in hsts[0].tags

    def test_parse_references(self, nuclei_output):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output(nuclei_output)
        wp = [f for f in findings if f.template_id == "outdated-wordpress"]
        assert len(wp[0].reference) >= 1

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        findings = parse_nuclei_output("")
        assert findings == []

    def test_parse_skips_invalid_json_lines(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        bad = 'not json\n{"template-id":"test","info":{"name":"Test","severity":"info","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        findings = parse_nuclei_output(bad)
        assert len(findings) == 1


class TestSeverityEnforcement:
    """Test that medium/high/critical findings are filtered out."""

    def test_filter_medium_severity(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        medium_line = '{"template-id":"sqli","info":{"name":"SQLi","severity":"medium","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        findings = parse_nuclei_output(medium_line)
        assert len(findings) == 0

    def test_filter_high_severity(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        high_line = '{"template-id":"rce","info":{"name":"RCE","severity":"high","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        findings = parse_nuclei_output(high_line)
        assert len(findings) == 0

    def test_filter_critical_severity(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        crit_line = '{"template-id":"rce-crit","info":{"name":"RCE Crit","severity":"critical","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        findings = parse_nuclei_output(crit_line)
        assert len(findings) == 0

    def test_keep_only_info_low(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        mixed = (
            '{"template-id":"a","info":{"name":"A","severity":"info","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
            '{"template-id":"b","info":{"name":"B","severity":"low","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
            '{"template-id":"c","info":{"name":"C","severity":"medium","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
            '{"template-id":"d","info":{"name":"D","severity":"high","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        )
        findings = parse_nuclei_output(mixed)
        assert len(findings) == 2
        assert {f.severity for f in findings} == {"info", "low"}


class TestNucleiScan:
    def test_nuclei_scan_with_mock(self, nuclei_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.analysis.nuclei import nuclei_scan

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0, stdout=nuclei_output, stderr="",
                duration_seconds=30.0, command=["nuclei"],
            )
        )

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            nuclei_scan("example.com", runner=mock_runner)
        )
        assert len(findings) == 4
        assert all(f.severity in ("info", "low") for f in findings)
