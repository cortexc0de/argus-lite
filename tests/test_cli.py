"""TDD: Tests for CLI skeleton — written BEFORE implementation."""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner


class TestCLIGroup:
    def test_main_help(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "argus-lite" in result.output.lower() or "security" in result.output.lower()

    def test_version_flag(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output


class TestScanCommand:
    def test_scan_requires_target(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0

    def test_scan_with_target(self):
        from argus_lite.cli import main

        runner = CliRunner()
        # Use --no-confirm to skip interactive prompt
        result = runner.invoke(main, ["scan", "example.com", "--no-confirm"])
        # Should not crash (may warn about tools not found, that's ok)
        assert result.exit_code == 0 or "error" not in result.output.lower().split("sanitization")[0]

    def test_scan_rejects_injection(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "example.com; rm -rf /", "--no-confirm"])
        assert result.exit_code != 0 or "forbidden" in result.output.lower() or "sanitization" in result.output.lower()

    def test_scan_preset_option(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert "--preset" in result.output

    def test_scan_output_option(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert "--output" in result.output

    def test_legal_notice_shown(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "example.com", "--no-confirm"])
        output = result.output.lower()
        assert "authorized" in output or "legal" in output or "permission" in output


class TestInitCommand:
    def test_init_creates_config(self):
        from argus_lite.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            os.environ["ARGUS_HOME"] = os.getcwd()
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0
            # Check that config file was created
            assert "created" in result.output.lower() or "initialized" in result.output.lower()
            del os.environ["ARGUS_HOME"]


class TestToolsCommand:
    def test_tools_check(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["tools", "check"])
        assert result.exit_code == 0


class TestListCommand:
    def test_list_scans(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["list"])
        assert result.exit_code == 0


class TestConfigCommand:
    def test_config_show(self):
        from argus_lite.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["config", "show"])
        assert result.exit_code == 0
