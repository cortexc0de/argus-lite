"""Shared fixtures for report tests — a complete ScanResult."""

from datetime import datetime, timezone

import pytest

from argus_lite.models.analysis import (
    AnalysisResult,
    NucleiFinding,
    Port,
    SecurityHeadersResult,
    SSLInfo,
    Technology,
)
from argus_lite.models.finding import Finding
from argus_lite.models.recon import CertificateInfo, DNSRecord, ReconResult, Subdomain, WhoisInfo
from argus_lite.models.scan import ScanResult


@pytest.fixture
def full_scan_result() -> ScanResult:
    """A realistic, complete ScanResult for testing report generation."""
    return ScanResult(
        scan_id="550e8400-e29b-41d4-a716-446655440000",
        target="example.com",
        target_type="domain",
        status="completed",
        started_at=datetime(2026, 3, 21, 10, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 21, 10, 15, 30, tzinfo=timezone.utc),
        recon=ReconResult(
            dns_records=[
                DNSRecord(type="A", name="example.com", value="93.184.216.34", ttl=300),
                DNSRecord(type="AAAA", name="example.com", value="2606:2800:220:1:248:1893:25c8:1946", ttl=300),
                DNSRecord(type="MX", name="example.com", value="10 mail.example.com", ttl=86400),
                DNSRecord(type="NS", name="example.com", value="ns1.example.com", ttl=86400),
            ],
            subdomains=[
                Subdomain(name="www.example.com", source="subfinder"),
                Subdomain(name="mail.example.com", source="subfinder"),
                Subdomain(name="api.example.com", source="crt.sh"),
            ],
            whois_info=WhoisInfo(
                domain="example.com",
                registrar="RESERVED-Internet Assigned Numbers Authority",
                creation_date="1995-08-14T04:00:00Z",
                expiration_date="2026-08-13T04:00:00Z",
                name_servers=["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
            ),
            certificate_info=CertificateInfo(
                subject="CN = www.example.org",
                issuer="CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                not_before="Jan 13 00:00:00 2026 GMT",
                not_after="Feb 13 23:59:59 2027 GMT",
                san=["www.example.org", "example.com", "www.example.com"],
            ),
        ),
        analysis=AnalysisResult(
            open_ports=[
                Port(port=22, protocol="tcp", service="ssh"),
                Port(port=80, protocol="tcp", service="http"),
                Port(port=443, protocol="tcp", service="https"),
            ],
            technologies=[
                Technology(name="WordPress", version="6.4.2", category="cms"),
                Technology(name="PHP", version="8.2.0", category="language"),
                Technology(name="Apache", version="2.4.58", category="server"),
            ],
            ssl_info=SSLInfo(
                protocol="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                issuer="DigiCert",
                subject="www.example.org",
                not_before="Jan 13 00:00:00 2026 GMT",
                not_after="Feb 13 23:59:59 2027 GMT",
            ),
            security_headers=SecurityHeadersResult(
                hsts=True,
                x_frame_options=True,
                x_content_type_options=True,
                csp=False,
                missing_headers=["content-security-policy", "referrer-policy", "permissions-policy"],
            ),
            nuclei_findings=[
                NucleiFinding(
                    template_id="missing-csp",
                    name="Missing CSP Header",
                    severity="info",
                    matched_at="https://example.com",
                    tags=["headers"],
                ),
                NucleiFinding(
                    template_id="outdated-wordpress",
                    name="Outdated WordPress",
                    severity="low",
                    matched_at="https://example.com/wp-login.php",
                    description="WordPress version is outdated",
                    tags=["wordpress", "outdated"],
                ),
            ],
        ),
        findings=[
            Finding(
                id="f-001",
                type="missing_header",
                severity="INFO",
                title="Missing Content-Security-Policy",
                description="CSP header not set",
                asset="example.com",
                evidence="Header not found",
                source="security_headers",
                remediation="Add CSP header",
            ),
            Finding(
                id="f-002",
                type="missing_header",
                severity="INFO",
                title="Missing Referrer-Policy",
                description="Referrer-Policy header not set",
                asset="example.com",
                evidence="Header not found",
                source="security_headers",
                remediation="Add Referrer-Policy header",
            ),
            Finding(
                id="f-003",
                type="outdated_software",
                severity="LOW",
                title="Outdated WordPress 6.4.2",
                description="WordPress version is outdated",
                asset="example.com",
                evidence="Detected version 6.4.2",
                source="nuclei",
                remediation="Update WordPress to latest version",
            ),
        ],
        tools_used=["dig", "whois", "subfinder", "openssl", "naabu", "whatweb", "nuclei"],
        completed_stages=["passive_recon", "active_recon", "service_detection", "vulnerability_scan", "report_generation"],
    )


@pytest.fixture
def empty_scan_result() -> ScanResult:
    """A minimal interrupted ScanResult."""
    return ScanResult(
        scan_id="minimal-uuid",
        target="test.local",
        target_type="domain",
        status="interrupted",
        started_at=datetime(2026, 3, 21, 10, 0, 0, tzinfo=timezone.utc),
        completed_stages=["passive_recon"],
        skipped_stages=["active_recon", "vulnerability_scan"],
    )
