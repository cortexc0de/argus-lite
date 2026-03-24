"""TDD: Tests for Correlation Engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from argus_lite.models.analysis import AnalysisResult, Port, SSLInfo, SecurityHeadersResult, Technology
from argus_lite.models.finding import Finding, Vulnerability
from argus_lite.models.recon import ReconResult, ShodanHostInfo


def _make_scan(techs=None, ports=None, findings=None, vulns=None, shodan=None, ssl=None, headers=None):
    from argus_lite.models.scan import ScanResult

    analysis = AnalysisResult(
        technologies=techs or [],
        open_ports=ports or [],
        ssl_info=ssl,
        security_headers=headers,
    )
    recon = ReconResult(shodan_info=shodan)

    return ScanResult(
        scan_id="test", target="example.com", target_type="domain",
        status="completed", started_at=datetime.now(tz=timezone.utc),
        analysis=analysis, recon=recon,
        findings=findings or [], vulnerabilities=vulns or [],
    )


class TestCorrelationEngine:
    def test_tech_with_cve_is_critical(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(
            techs=[Technology(name="WordPress", version="6.3", category="cms")],
            vulns=[Vulnerability(id="v1", finding_id="", cve="CVE-2024-1234", cvss_score=8.5)],
        )
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score >= 20  # elevated due to HIGH CVE
        assert any("CVE-2024-1234" in c for c in result.correlations)

    def test_exposed_port_with_cve_elevates_risk(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(
            ports=[Port(port=22, protocol="tcp", service="ssh")],
            vulns=[Vulnerability(id="v1", finding_id="", cve="CVE-2024-5678", cvss_score=9.0)],
        )
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score > 30

    def test_shodan_vulns_boost_risk(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(
            shodan=ShodanHostInfo(ip="1.1.1.1", vulns=["CVE-2024-1111", "CVE-2024-2222"]),
        )
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score > 0
        assert len(result.correlations) >= 1

    def test_missing_headers_plus_tech_flag(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(
            techs=[Technology(name="WordPress", version="6.0")],
            headers=SecurityHeadersResult(
                missing_headers=["Strict-Transport-Security", "Content-Security-Policy"],
            ),
        )
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score > 0

    def test_ssl_expired_elevates(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(ssl=SSLInfo(expired=True, protocol="TLSv1.2"))
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score >= 15

    def test_empty_scan_zero_risk(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan()
        result = CorrelationEngine.correlate(scan)
        assert result.risk_score == 0
        assert result.correlations == []

    def test_result_has_attack_surface_level(self):
        from argus_lite.core.correlation import CorrelationEngine

        scan = _make_scan(
            ports=[Port(port=80, protocol="tcp"), Port(port=443, protocol="tcp"),
                   Port(port=22, protocol="tcp"), Port(port=8080, protocol="tcp")],
            techs=[Technology(name="Apache", version="2.4")],
            vulns=[Vulnerability(id="v1", finding_id="", cve="CVE-2024-9999", cvss_score=7.0)],
        )
        result = CorrelationEngine.correlate(scan)
        assert result.attack_surface in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
