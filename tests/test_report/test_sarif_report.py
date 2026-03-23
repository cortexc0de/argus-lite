"""TDD: Tests for SARIF output."""

import json

import pytest


class TestSarifReport:
    def test_valid_sarif_structure(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        assert sarif["version"] == "2.1.0"

    def test_has_runs(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        assert len(sarif["runs"]) == 1

    def test_tool_info(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Argus"
        assert "1.0" in tool["version"]

    def test_results_count(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        results = sarif["runs"][0]["results"]
        assert len(results) == len(full_scan_result.findings)

    def test_result_has_rule_id(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        for result in sarif["runs"][0]["results"]:
            assert "ruleId" in result

    def test_result_has_level(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        for result in sarif["runs"][0]["results"]:
            assert result["level"] in ("note", "warning", "error")

    def test_result_has_message(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        for result in sarif["runs"][0]["results"]:
            assert "text" in result["message"]

    def test_result_has_location(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        for result in sarif["runs"][0]["results"]:
            assert len(result["locations"]) >= 1
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "example.com" in uri

    def test_rules_defined(self, full_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(full_scan_result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

    def test_empty_scan(self, empty_scan_result):
        from argus_lite.modules.report.sarif_report import generate_sarif_report

        sarif = json.loads(generate_sarif_report(empty_scan_result))
        assert sarif["runs"][0]["results"] == []

    def test_write_to_file(self, full_scan_result, tmp_path):
        from argus_lite.modules.report.sarif_report import write_sarif_report

        out = tmp_path / "report.sarif"
        write_sarif_report(full_scan_result, out)
        assert out.exists()
        sarif = json.loads(out.read_text())
        assert sarif["version"] == "2.1.0"
