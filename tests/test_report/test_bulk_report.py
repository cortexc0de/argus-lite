"""TDD: Tests for bulk scan report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _make_bulk_result(n_targets: int = 2):
    from argus_lite.models.bulk import BulkScanResult, BulkScanSummary
    from argus_lite.models.scan import ScanResult

    scans = []
    for i in range(n_targets):
        scans.append(ScanResult(
            scan_id=f"scan-{i}",
            target=f"host{i}.example.com",
            target_type="domain",
            status="completed",
            started_at=datetime.now(tz=timezone.utc),
        ))

    return BulkScanResult(
        bulk_id="bulk-test-001",
        sources=["targets.txt"],
        scan_results=scans,
        failed_targets=["dead.example.com"],
        summary=BulkScanSummary(
            total_targets=n_targets + 1,
            completed=n_targets,
            failed=1,
            live_hosts=n_targets,
            total_findings=5,
            total_vulnerabilities=2,
            highest_risk="LOW",
            technologies_seen=["WordPress", "Apache"],
            top_cves=["CVE-2023-1234"],
        ),
        started_at=datetime.now(tz=timezone.utc),
        completed_at=datetime.now(tz=timezone.utc),
    )


class TestGenerateBulkSummaryHtml:
    def test_returns_string(self):
        from argus_lite.modules.report.bulk_report import generate_bulk_summary_html

        html = generate_bulk_summary_html(_make_bulk_result())
        assert isinstance(html, str)
        assert len(html) > 100

    def test_contains_bulk_id(self):
        from argus_lite.modules.report.bulk_report import generate_bulk_summary_html

        html = generate_bulk_summary_html(_make_bulk_result())
        assert "bulk-test-001" in html

    def test_contains_target_names(self):
        from argus_lite.modules.report.bulk_report import generate_bulk_summary_html

        html = generate_bulk_summary_html(_make_bulk_result())
        assert "host0.example.com" in html
        assert "host1.example.com" in html

    def test_shows_failed_targets(self):
        from argus_lite.modules.report.bulk_report import generate_bulk_summary_html

        html = generate_bulk_summary_html(_make_bulk_result())
        assert "dead.example.com" in html

    def test_shows_summary_stats(self):
        from argus_lite.modules.report.bulk_report import generate_bulk_summary_html

        html = generate_bulk_summary_html(_make_bulk_result())
        assert "LOW" in html  # highest risk

    def test_write_creates_file(self, tmp_path):
        from argus_lite.modules.report.bulk_report import write_bulk_report

        write_bulk_report(_make_bulk_result(), tmp_path)
        assert (tmp_path / "summary.html").exists()
