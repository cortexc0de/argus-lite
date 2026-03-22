"""TDD: Tests for new v2 models — written BEFORE implementation."""

import pytest
from pydantic import ValidationError


class TestNewReconModels:
    def test_http_probe(self):
        from argus_lite.models.recon import HttpProbe

        p = HttpProbe(url="https://example.com", status_code=200, title="Example", content_length=1256, tech=["Apache"], response_time_ms=120)
        assert p.status_code == 200
        assert "Apache" in p.tech

    def test_crawl_result(self):
        from argus_lite.models.recon import CrawlResult

        c = CrawlResult(url="https://example.com/api/v1", method="GET", source="https://example.com", tag="a")
        assert c.url == "https://example.com/api/v1"

    def test_historical_url(self):
        from argus_lite.models.recon import HistoricalUrl

        h = HistoricalUrl(url="https://example.com/admin.php", source="wayback")
        assert h.source == "wayback"

    def test_dns_resolution(self):
        from argus_lite.models.recon import DnsResolution

        d = DnsResolution(host="sub.example.com", a=["1.2.3.4"], cname=["cdn.example.com"], wildcard=False)
        assert d.a == ["1.2.3.4"]
        assert d.wildcard is False

    def test_tls_cert(self):
        from argus_lite.models.recon import TlsCert

        t = TlsCert(host="example.com", subject_cn="*.example.com", issuer="DigiCert", san=["example.com", "www.example.com"], not_after="2027-01-01", expired=False)
        assert "*.example.com" in t.subject_cn

    def test_recon_result_extended(self):
        from argus_lite.models.recon import HttpProbe, ReconResult

        r = ReconResult(http_probes=[HttpProbe(url="https://x.com", status_code=200, title="X")])
        assert len(r.http_probes) == 1


class TestNewAnalysisModels:
    def test_ffuf_result(self):
        from argus_lite.models.analysis import FfufResult

        f = FfufResult(url="https://example.com/admin", status_code=200, content_length=5432, words=100, lines=50)
        assert f.status_code == 200

    def test_analysis_result_extended(self):
        from argus_lite.models.analysis import AnalysisResult, FfufResult

        r = AnalysisResult(fuzz_results=[FfufResult(url="https://x.com/.git", status_code=403, content_length=0)])
        assert len(r.fuzz_results) == 1


class TestRiskModels:
    def test_risk_summary(self):
        from argus_lite.models.risk import RiskSummary

        r = RiskSummary(overall_score=35, risk_level="MEDIUM", breakdown={"findings": 15, "headers": 10, "ssl": 5, "services": 5})
        assert r.risk_level == "MEDIUM"
        assert r.overall_score == 35

    def test_risk_level_validation(self):
        from argus_lite.models.risk import RiskSummary

        for level in ("NONE", "LOW", "MEDIUM", "HIGH"):
            r = RiskSummary(overall_score=0, risk_level=level)
            assert r.risk_level == level

        with pytest.raises(ValidationError):
            RiskSummary(overall_score=0, risk_level="CRITICAL_MELTDOWN")

    def test_scan_result_has_risk(self):
        from datetime import datetime, timezone
        from argus_lite.models.risk import RiskSummary
        from argus_lite.models.scan import ScanResult

        r = ScanResult(
            scan_id="t", target="t.com", target_type="domain",
            status="completed", started_at=datetime.now(tz=timezone.utc),
            risk_summary=RiskSummary(overall_score=10, risk_level="LOW"),
        )
        assert r.risk_summary.risk_level == "LOW"
