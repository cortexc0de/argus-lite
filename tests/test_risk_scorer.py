"""TDD: Tests for risk scoring — written BEFORE implementation."""

from datetime import datetime, timezone

import pytest

from argus_lite.models.analysis import AnalysisResult, SecurityHeadersResult, SSLInfo
from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult


def _scan(**kwargs) -> ScanResult:
    defaults = dict(
        scan_id="t", target="t.com", target_type="domain",
        status="completed", started_at=datetime.now(tz=timezone.utc),
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _finding(severity="INFO") -> Finding:
    return Finding(
        id="f1", type="test", severity=severity, title="T",
        description="D", asset="a", evidence="e", source="s", remediation="r",
    )


class TestRiskScorer:
    def test_empty_scan_is_none(self):
        from argus_lite.core.risk_scorer import score_scan

        result = score_scan(_scan())
        assert result.risk_level == "NONE"
        assert result.overall_score == 0

    def test_info_findings_add_small_score(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(findings=[_finding("INFO"), _finding("INFO")])
        result = score_scan(s)
        assert result.overall_score > 0
        assert result.risk_level == "LOW"

    def test_low_findings_add_more_score(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(findings=[_finding("LOW"), _finding("LOW"), _finding("LOW")])
        result = score_scan(s)
        assert result.overall_score > 5

    def test_missing_headers_add_penalty(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(analysis=AnalysisResult(
            security_headers=SecurityHeadersResult(
                missing_headers=["hsts", "csp", "x-frame-options", "referrer-policy"]
            )
        ))
        result = score_scan(s)
        assert result.breakdown.get("headers", 0) > 0

    def test_weak_ssl_adds_penalty(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(analysis=AnalysisResult(
            ssl_info=SSLInfo(weak_cipher=True)
        ))
        result = score_scan(s)
        assert result.breakdown.get("ssl", 0) > 0

    def test_expired_ssl_adds_penalty(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(analysis=AnalysisResult(
            ssl_info=SSLInfo(expired=True)
        ))
        result = score_scan(s)
        assert result.breakdown.get("ssl", 0) > 0

    def test_risk_levels(self):
        from argus_lite.core.risk_scorer import _compute_risk_level

        assert _compute_risk_level(0) == "NONE"
        assert _compute_risk_level(10) == "LOW"
        assert _compute_risk_level(30) == "MEDIUM"
        assert _compute_risk_level(60) == "HIGH"

    def test_combined_score(self):
        from argus_lite.core.risk_scorer import score_scan

        s = _scan(
            findings=[_finding("LOW"), _finding("INFO")],
            analysis=AnalysisResult(
                security_headers=SecurityHeadersResult(
                    missing_headers=["hsts", "csp"]
                ),
                ssl_info=SSLInfo(weak_cipher=True),
            ),
        )
        result = score_scan(s)
        assert result.overall_score > 10
        assert "findings" in result.breakdown
        assert "headers" in result.breakdown
        assert "ssl" in result.breakdown
