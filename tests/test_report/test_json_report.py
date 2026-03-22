"""TDD: Tests for JSON report — written BEFORE implementation."""

import json

import pytest


class TestJsonReport:
    def test_generate_valid_json(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        output = generate_json_report(full_scan_result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_contains_scan_metadata(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(full_scan_result))
        assert data["scan_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert data["target"] == "example.com"
        assert data["status"] == "completed"

    def test_contains_summary(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(full_scan_result))
        summary = data["summary"]
        assert summary["dns_records"] == 4
        assert summary["subdomains"] == 3
        assert summary["open_ports"] == 3
        assert summary["technologies"] == 3
        assert summary["findings"] == 3

    def test_contains_findings(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(full_scan_result))
        assert len(data["findings"]) == 3
        assert data["findings"][0]["severity"] in ("INFO", "LOW")

    def test_contains_tools_used(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(full_scan_result))
        assert "nuclei" in data["tools_used"]

    def test_contains_legal_notice(self, full_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(full_scan_result))
        assert "legal_notice" in data
        assert "authorized" in data["legal_notice"].lower()

    def test_empty_scan_result(self, empty_scan_result):
        from argus_lite.modules.report.json_report import generate_json_report

        data = json.loads(generate_json_report(empty_scan_result))
        assert data["status"] == "interrupted"
        assert data["summary"]["findings"] == 0

    def test_write_to_file(self, full_scan_result, tmp_path):
        from argus_lite.modules.report.json_report import write_json_report

        out_file = tmp_path / "report.json"
        write_json_report(full_scan_result, out_file)
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["target"] == "example.com"
