"""Tests for HTML report."""

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
        assert "badge-info" in html or "sev-info" in html
        assert "badge-low" in html or "sev-low" in html

    def test_contains_summary_cards(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "Findings" in html
        assert "Security Headers" in html

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

    def test_only_relevant_ports_shown(self, full_scan_result):
        """Ports without services should not appear in HTML report."""
        from argus_lite.models.analysis import Port
        from argus_lite.modules.report.html_report import generate_html_report

        # Add a port with no service
        full_scan_result.analysis.open_ports.append(
            Port(port=31337, protocol="tcp", service="", banner="")
        )
        html = generate_html_report(full_scan_result)
        assert "31337" not in html  # Empty-service port filtered out

    def test_dark_theme(self, full_scan_result):
        from argus_lite.modules.report.html_report import generate_html_report

        html = generate_html_report(full_scan_result)
        assert "#0d1117" in html  # Dark background
