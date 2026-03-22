"""TDD: Tests for Markdown report — written BEFORE implementation."""

import pytest


class TestMarkdownReport:
    def test_contains_title(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "# Security Scan Report" in md

    def test_contains_target(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "example.com" in md

    def test_contains_summary_table(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "| Metric" in md
        assert "Subdomains" in md
        assert "Open Ports" in md

    def test_contains_dns_section(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "## DNS Records" in md
        assert "93.184.216.34" in md

    def test_contains_ports_section(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "## Open Ports" in md
        assert "443" in md
        assert "https" in md

    def test_contains_technologies_section(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "## Technologies" in md
        assert "WordPress" in md
        assert "6.4.2" in md

    def test_contains_findings_section(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "## Findings" in md
        assert "[INFO]" in md
        assert "[LOW]" in md

    def test_contains_ssl_info(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "TLSv1.3" in md

    def test_contains_legal_notice(self, full_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(full_scan_result)
        assert "authorized" in md.lower()

    def test_empty_scan(self, empty_scan_result):
        from argus_lite.modules.report.markdown_report import generate_markdown_report

        md = generate_markdown_report(empty_scan_result)
        assert "interrupted" in md.lower()
        assert "# Security Scan Report" in md

    def test_write_to_file(self, full_scan_result, tmp_path):
        from argus_lite.modules.report.markdown_report import write_markdown_report

        out_file = tmp_path / "report.md"
        write_markdown_report(full_scan_result, out_file)
        assert out_file.exists()
        assert "example.com" in out_file.read_text()
