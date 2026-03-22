"""TDD: Tests for HTML report — written BEFORE implementation."""

import pytest


class TestHtmlReport:
    def test_valid_html(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "<html" in html
        assert "</html>" in html

    def test_contains_target(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "example.com" in html

    def test_contains_findings(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "Missing Content-Security-Policy" in html

    def test_severity_color_coding(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        # Should have CSS classes or inline styles for severity
        assert "info" in html.lower()
        assert "low" in html.lower()

    def test_contains_summary_stats(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "Open Ports" in html or "open_ports" in html
        assert "3" in html  # 3 ports

    def test_contains_legal_notice(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "authorized" in html.lower()

    def test_empty_scan(self, empty_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(empty_scan_result)
        assert "<html" in html
        assert "interrupted" in html.lower()

    def test_write_to_file(self, full_scan_result, tmp_path):
        from argus_lite.modules.report.html_report import write_html_report

        out_file = tmp_path / "report.html"
        write_html_report(full_scan_result, out_file)
        assert out_file.exists()
        content = out_file.read_text()
        assert "<html" in content
