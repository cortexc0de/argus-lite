"""TDD: Tests for BulkScanner — written BEFORE implementation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_completed_result(target: str, risk: str = "NONE"):
    from argus_lite.models.finding import Finding, Vulnerability
    from argus_lite.models.risk import RiskSummary
    from argus_lite.models.scan import ScanResult

    result = ScanResult(
        scan_id=f"scan-{target}",
        target=target,
        target_type="domain",
        status="completed",
        started_at=datetime.now(tz=timezone.utc),
    )
    result.risk_summary = RiskSummary(
        risk_level=risk,
        overall_score={"NONE": 0, "LOW": 10, "MEDIUM": 30, "HIGH": 60}.get(risk, 0),
    )
    return result


@pytest.fixture
def config():
    from argus_lite.core.config import AppConfig
    return AppConfig()


class TestBulkScannerInstantiation:
    def test_creates_with_defaults(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        scanner = BulkScanner(config=config)
        assert scanner is not None

    def test_accepts_callbacks(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        started = []
        done = []

        scanner = BulkScanner(
            config=config,
            on_target_start=lambda t: started.append(t),
            on_target_done=lambda t, r: done.append(t),
        )
        assert scanner._on_target_start is not None
        assert scanner._on_target_done is not None


class TestBulkScannerRun:
    def test_empty_targets_returns_empty_result(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        scanner = BulkScanner(config=config)
        result = asyncio.get_event_loop().run_until_complete(scanner.run([]))
        assert result.summary.total_targets == 0
        assert result.scan_results == []

    def test_scans_multiple_targets(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        mock_result_a = _make_completed_result("a.com")
        mock_result_b = _make_completed_result("b.com")

        call_count = [0]

        async def mock_run(self_orch):
            call_count[0] += 1
            target = self_orch.target
            return _make_completed_result(target)

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
            scanner = BulkScanner(config=config, concurrency=2)
            result = asyncio.get_event_loop().run_until_complete(
                scanner.run(["a.com", "b.com"])
            )

        assert len(result.scan_results) == 2
        assert result.summary.completed == 2
        assert result.summary.failed == 0

    def test_failed_target_recorded(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        async def mock_run_fail(self_orch):
            raise RuntimeError("connection refused")

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run_fail):
            scanner = BulkScanner(config=config)
            result = asyncio.get_event_loop().run_until_complete(
                scanner.run(["fail.example.com"])
            )

        assert "fail.example.com" in result.failed_targets
        assert result.summary.failed == 1
        assert result.summary.completed == 0

    def test_partial_failure_does_not_abort(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        call_targets = []

        async def mock_run_mixed(self_orch):
            call_targets.append(self_orch.target)
            if self_orch.target == "bad.com":
                raise RuntimeError("failed")
            return _make_completed_result(self_orch.target)

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run_mixed):
            scanner = BulkScanner(config=config, concurrency=1)
            result = asyncio.get_event_loop().run_until_complete(
                scanner.run(["good.com", "bad.com", "also-good.com"])
            )

        assert len(result.scan_results) == 2
        assert result.summary.completed == 2
        assert result.summary.failed == 1

    def test_concurrency_respects_limit(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        concurrent_count = [0]
        max_seen = [0]

        async def mock_run_slow(self_orch):
            concurrent_count[0] += 1
            max_seen[0] = max(max_seen[0], concurrent_count[0])
            await asyncio.sleep(0.05)
            concurrent_count[0] -= 1
            return _make_completed_result(self_orch.target)

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run_slow):
            scanner = BulkScanner(config=config, concurrency=2)
            asyncio.get_event_loop().run_until_complete(
                scanner.run(["t1.com", "t2.com", "t3.com", "t4.com"])
            )

        assert max_seen[0] <= 2


class TestComputeSummary:
    def test_aggregates_risk_levels(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        scanner = BulkScanner(config=config)
        results = [
            _make_completed_result("a.com", "LOW"),
            _make_completed_result("b.com", "NONE"),
        ]
        summary = scanner._compute_summary(results, [])
        assert summary.highest_risk == "LOW"

    def test_counts_failed(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner

        scanner = BulkScanner(config=config)
        summary = scanner._compute_summary([], ["x.com", "y.com"])
        assert summary.failed == 2
        assert summary.completed == 0

    def test_deduplicates_technologies(self, config):
        from argus_lite.core.bulk_scanner import BulkScanner
        from argus_lite.models.analysis import AnalysisResult, Technology

        scanner = BulkScanner(config=config)
        r1 = _make_completed_result("a.com")
        r2 = _make_completed_result("b.com")
        r1.analysis.technologies = [Technology(name="WordPress", version="6.0")]
        r2.analysis.technologies = [Technology(name="WordPress", version="6.1"), Technology(name="Apache", version="2.4")]

        summary = scanner._compute_summary([r1, r2], [])
        assert "WordPress" in summary.technologies_seen
        assert "Apache" in summary.technologies_seen
        assert summary.technologies_seen.count("WordPress") == 1
