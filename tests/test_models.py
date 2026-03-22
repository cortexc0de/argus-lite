"""TDD: Tests for Pydantic data models — written BEFORE implementation."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError


class TestFinding:
    def test_create_valid_finding(self):
        from argus_lite.models.finding import Finding

        f = Finding(
            id="f-001",
            type="missing_header",
            severity="INFO",
            title="Missing HSTS Header",
            description="The HSTS header is not set.",
            asset="example.com",
            evidence="Header not found in response",
            source="security_headers",
            remediation="Add Strict-Transport-Security header",
        )
        assert f.id == "f-001"
        assert f.severity == "INFO"
        assert f.false_positive is False

    def test_finding_severity_validation_allows_info_low(self):
        from argus_lite.models.finding import Finding

        for sev in ("INFO", "LOW"):
            f = Finding(
                id="f-001",
                type="test",
                severity=sev,
                title="Test",
                description="Test",
                asset="test.com",
                evidence="none",
                source="test",
                remediation="none",
            )
            assert f.severity == sev

    def test_finding_severity_rejects_high_critical(self):
        from argus_lite.models.finding import Finding

        for sev in ("MEDIUM", "HIGH", "CRITICAL"):
            with pytest.raises(ValidationError):
                Finding(
                    id="f-001",
                    type="test",
                    severity=sev,
                    title="Test",
                    description="Test",
                    asset="test.com",
                    evidence="none",
                    source="test",
                    remediation="none",
                )

    def test_finding_json_roundtrip(self):
        from argus_lite.models.finding import Finding

        f = Finding(
            id="f-001",
            type="missing_header",
            severity="LOW",
            title="Test",
            description="Desc",
            asset="test.com",
            evidence="ev",
            source="src",
            remediation="fix it",
        )
        json_str = f.model_dump_json()
        f2 = Finding.model_validate_json(json_str)
        assert f == f2


class TestVulnerability:
    def test_create_vulnerability(self):
        from argus_lite.models.finding import Vulnerability

        v = Vulnerability(
            id="v-001",
            finding_id="f-001",
            cve="CVE-2024-1234",
            cvss_score=3.5,
        )
        assert v.cve == "CVE-2024-1234"
        assert v.exploit_available is False
        assert v.references == []

    def test_vulnerability_optional_fields(self):
        from argus_lite.models.finding import Vulnerability

        v = Vulnerability(id="v-001", finding_id="f-001")
        assert v.cve is None
        assert v.cvss_score is None
        assert v.cvss_vector is None


class TestReconResult:
    def test_default_empty(self):
        from argus_lite.models.recon import ReconResult

        r = ReconResult()
        assert r.dns_records == []
        assert r.subdomains == []
        assert r.whois_info is None
        assert r.certificate_info is None

    def test_add_dns_record(self):
        from argus_lite.models.recon import DNSRecord, ReconResult

        r = ReconResult(
            dns_records=[
                DNSRecord(type="A", name="example.com", value="93.184.216.34", ttl=300)
            ]
        )
        assert len(r.dns_records) == 1
        assert r.dns_records[0].type == "A"


class TestAnalysisResult:
    def test_default_empty(self):
        from argus_lite.models.analysis import AnalysisResult

        r = AnalysisResult()
        assert r.open_ports == []
        assert r.technologies == []
        assert r.ssl_info is None
        assert r.nuclei_findings == []

    def test_add_port(self):
        from argus_lite.models.analysis import AnalysisResult, Port

        r = AnalysisResult(
            open_ports=[Port(port=443, protocol="tcp", service="https", banner="")]
        )
        assert r.open_ports[0].port == 443


class TestScanResult:
    def test_create_minimal(self):
        from argus_lite.models.scan import ScanResult

        now = datetime.now(tz=timezone.utc)
        s = ScanResult(
            scan_id="test-uuid",
            target="example.com",
            target_type="domain",
            status="running",
            started_at=now,
        )
        assert s.scan_id == "test-uuid"
        assert s.completed_at is None
        assert s.completed_stages == []
        assert s.errors == []

    def test_scan_result_aggregates_modules(self):
        from argus_lite.models.analysis import AnalysisResult, Port
        from argus_lite.models.recon import DNSRecord, ReconResult
        from argus_lite.models.scan import ScanResult

        now = datetime.now(tz=timezone.utc)
        s = ScanResult(
            scan_id="test-uuid",
            target="example.com",
            target_type="domain",
            status="completed",
            started_at=now,
            completed_at=now,
            recon=ReconResult(
                dns_records=[
                    DNSRecord(
                        type="A", name="example.com", value="1.2.3.4", ttl=300
                    )
                ]
            ),
            analysis=AnalysisResult(
                open_ports=[
                    Port(port=80, protocol="tcp", service="http", banner="")
                ]
            ),
            completed_stages=["passive_recon", "active_recon"],
        )
        assert len(s.recon.dns_records) == 1
        assert len(s.analysis.open_ports) == 1
        assert "passive_recon" in s.completed_stages

    def test_scan_result_json_roundtrip(self):
        from argus_lite.models.scan import ScanResult

        now = datetime.now(tz=timezone.utc)
        s = ScanResult(
            scan_id="test-uuid",
            target="example.com",
            target_type="domain",
            status="running",
            started_at=now,
        )
        json_str = s.model_dump_json()
        s2 = ScanResult.model_validate_json(json_str)
        assert s.scan_id == s2.scan_id

    def test_scan_status_validation(self):
        from argus_lite.models.scan import ScanResult

        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            ScanResult(
                scan_id="test",
                target="test.com",
                target_type="domain",
                status="invalid_status",
                started_at=now,
            )
