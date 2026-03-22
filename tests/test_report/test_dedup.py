"""TDD: Tests for finding deduplication and summary stats."""

import pytest

from argus_lite.models.finding import Finding


def _make_finding(id: str, title: str, severity: str = "INFO", source: str = "test") -> Finding:
    return Finding(
        id=id, type="test", severity=severity, title=title,
        description="desc", asset="test.com", evidence="ev",
        source=source, remediation="fix",
    )


class TestDeduplication:
    def test_dedup_by_title(self):
        from argus_lite.modules.report.dedup import deduplicate_findings

        findings = [
            _make_finding("f1", "Missing HSTS", source="security_headers"),
            _make_finding("f2", "Missing HSTS", source="nuclei"),
            _make_finding("f3", "Missing CSP"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_dedup_preserves_first(self):
        from argus_lite.modules.report.dedup import deduplicate_findings

        findings = [
            _make_finding("f1", "Missing HSTS", source="security_headers"),
            _make_finding("f2", "Missing HSTS", source="nuclei"),
        ]
        result = deduplicate_findings(findings)
        assert result[0].id == "f1"

    def test_dedup_empty(self):
        from argus_lite.modules.report.dedup import deduplicate_findings

        result = deduplicate_findings([])
        assert result == []

    def test_dedup_no_duplicates(self):
        from argus_lite.modules.report.dedup import deduplicate_findings

        findings = [
            _make_finding("f1", "A"),
            _make_finding("f2", "B"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2


class TestFilterRelevantPorts:
    def test_filters_empty_service(self, full_scan_result):
        from argus_lite.models.analysis import Port
        from argus_lite.modules.report.dedup import filter_relevant_ports

        full_scan_result.analysis.open_ports.append(
            Port(port=99999, protocol="tcp", service="", banner="")
        )
        relevant = filter_relevant_ports(full_scan_result)
        assert all(p.service for p in relevant)
        assert not any(p.port == 99999 for p in relevant)

    def test_keeps_ports_with_service(self, full_scan_result):
        from argus_lite.modules.report.dedup import filter_relevant_ports

        relevant = filter_relevant_ports(full_scan_result)
        assert len(relevant) == 3  # ssh, http, https


class TestSummaryStats:
    def test_compute_stats(self, full_scan_result):
        from argus_lite.modules.report.dedup import compute_summary

        stats = compute_summary(full_scan_result)
        assert stats["dns_records"] == 4
        assert stats["subdomains"] == 3
        assert stats["open_ports"] == 3
        assert stats["technologies"] == 3
        assert stats["findings"] == 3
        assert stats["info_count"] == 2
        assert stats["low_count"] == 1

    def test_compute_stats_empty(self, empty_scan_result):
        from argus_lite.modules.report.dedup import compute_summary

        stats = compute_summary(empty_scan_result)
        assert stats["dns_records"] == 0
        assert stats["findings"] == 0

    def test_stats_includes_scan_duration(self, full_scan_result):
        from argus_lite.modules.report.dedup import compute_summary

        stats = compute_summary(full_scan_result)
        assert "duration_seconds" in stats
        assert stats["duration_seconds"] > 0
