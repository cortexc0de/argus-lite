"""TDD: Tests for BulkScan models — written BEFORE implementation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest


def _make_scan_result(target: str, risk: str = "NONE", finding_count: int = 0):
    from argus_lite.models.scan import ScanResult

    return ScanResult(
        scan_id=f"scan-{target}",
        target=target,
        target_type="domain",
        status="completed",
        started_at=datetime.now(tz=timezone.utc),
    )


class TestBulkScanSummary:
    def test_default_values(self):
        from argus_lite.models.bulk import BulkScanSummary

        s = BulkScanSummary(
            total_targets=10,
            completed=8,
            failed=2,
            live_hosts=6,
            total_findings=15,
            total_vulnerabilities=3,
        )
        assert s.highest_risk == "NONE"
        assert s.technologies_seen == []
        assert s.top_cves == []
        assert s.findings_by_severity == {}

    def test_all_fields(self):
        from argus_lite.models.bulk import BulkScanSummary

        s = BulkScanSummary(
            total_targets=5,
            completed=5,
            failed=0,
            live_hosts=4,
            total_findings=20,
            total_vulnerabilities=5,
            highest_risk="HIGH",
            technologies_seen=["WordPress", "Apache"],
            top_cves=["CVE-2023-1234"],
            findings_by_severity={"INFO": 15, "LOW": 5},
        )
        assert s.highest_risk == "HIGH"
        assert len(s.technologies_seen) == 2
        assert s.top_cves[0] == "CVE-2023-1234"


class TestBulkScanResult:
    def test_instantiation(self):
        from argus_lite.models.bulk import BulkScanResult, BulkScanSummary

        result = BulkScanResult(
            bulk_id="bulk-001",
            sources=["targets.txt"],
            summary=BulkScanSummary(
                total_targets=3, completed=3, failed=0,
                live_hosts=2, total_findings=5, total_vulnerabilities=0,
            ),
            started_at=datetime.now(tz=timezone.utc),
        )
        assert result.bulk_id == "bulk-001"
        assert result.sources == ["targets.txt"]
        assert result.scan_results == []
        assert result.failed_targets == []
        assert result.completed_at is None
        assert result.preset == "bulk"

    def test_with_scan_results(self):
        from argus_lite.models.bulk import BulkScanResult, BulkScanSummary

        sr1 = _make_scan_result("a.com")
        sr2 = _make_scan_result("b.com")

        result = BulkScanResult(
            bulk_id="bulk-002",
            sources=["a.com", "b.com"],
            scan_results=[sr1, sr2],
            summary=BulkScanSummary(
                total_targets=2, completed=2, failed=0,
                live_hosts=2, total_findings=0, total_vulnerabilities=0,
            ),
            started_at=datetime.now(tz=timezone.utc),
        )
        assert len(result.scan_results) == 2

    def test_failed_targets_recorded(self):
        from argus_lite.models.bulk import BulkScanResult, BulkScanSummary

        result = BulkScanResult(
            bulk_id="bulk-003",
            sources=["targets.txt"],
            failed_targets=["unreachable.example.com"],
            summary=BulkScanSummary(
                total_targets=1, completed=0, failed=1,
                live_hosts=0, total_findings=0, total_vulnerabilities=0,
            ),
            started_at=datetime.now(tz=timezone.utc),
        )
        assert "unreachable.example.com" in result.failed_targets

    def test_serialization(self):
        from argus_lite.models.bulk import BulkScanResult, BulkScanSummary

        result = BulkScanResult(
            bulk_id="bulk-004",
            sources=["192.168.1.0/24"],
            summary=BulkScanSummary(
                total_targets=0, completed=0, failed=0,
                live_hosts=0, total_findings=0, total_vulnerabilities=0,
            ),
            started_at=datetime.now(tz=timezone.utc),
        )
        data = result.model_dump()
        assert data["bulk_id"] == "bulk-004"
        assert "summary" in data
