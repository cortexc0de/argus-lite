"""Correlation Engine — cross-reference OSINT + findings + CVEs for attack surface scoring."""

from __future__ import annotations

from dataclasses import dataclass, field

from argus_lite.models.scan import ScanResult


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""

    risk_score: int = 0
    attack_surface: str = "LOW"    # LOW / MEDIUM / HIGH / CRITICAL
    correlations: list[str] = field(default_factory=list)


class CorrelationEngine:
    """Cross-reference OSINT data, findings, and CVEs to compute true attack surface."""

    @staticmethod
    def correlate(scan: ScanResult) -> CorrelationResult:
        """Analyze a ScanResult and compute correlated risk."""
        score = 0
        correlations: list[str] = []

        # 1. Technology + CVE correlation
        tech_names = {t.name.lower() for t in scan.analysis.technologies}
        for vuln in scan.vulnerabilities:
            if vuln.cve and vuln.cvss_score:
                # Each CVE with CVSS >= 7.0 is high-impact
                if vuln.cvss_score >= 9.0:
                    score += 30
                    correlations.append(f"CRITICAL CVE: {vuln.cve} (CVSS {vuln.cvss_score})")
                elif vuln.cvss_score >= 7.0:
                    score += 20
                    correlations.append(f"HIGH CVE: {vuln.cve} (CVSS {vuln.cvss_score})")
                else:
                    score += 10
                    correlations.append(f"CVE: {vuln.cve} (CVSS {vuln.cvss_score})")

        # 2. Exposed ports + CVE = amplified risk
        open_ports = {p.port for p in scan.analysis.open_ports}
        risky_ports = {21, 22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}
        exposed_risky = open_ports & risky_ports
        if exposed_risky and scan.vulnerabilities:
            score += len(exposed_risky) * 5
            correlations.append(
                f"Risky ports exposed with known CVEs: {', '.join(str(p) for p in exposed_risky)}"
            )

        # 3. Shodan vulns (external validation)
        shodan = scan.recon.shodan_info
        if shodan and shodan.vulns:
            score += len(shodan.vulns) * 8
            correlations.append(
                f"Shodan reports {len(shodan.vulns)} CVEs: {', '.join(shodan.vulns[:5])}"
            )

        # 4. Missing security headers + known tech = attack vector
        headers = scan.analysis.security_headers
        if headers and headers.missing_headers and tech_names:
            critical_missing = {"strict-transport-security", "content-security-policy"}
            missing_lower = {h.lower().replace("-", "-") for h in headers.missing_headers}
            if critical_missing & missing_lower:
                score += 5
                correlations.append(
                    f"Missing critical headers on known stack: {', '.join(tech_names)}"
                )

        # 5. SSL issues
        ssl = scan.analysis.ssl_info
        if ssl:
            if ssl.expired:
                score += 15
                correlations.append("SSL certificate EXPIRED")
            if ssl.weak_cipher:
                score += 10
                correlations.append("Weak SSL cipher detected")

        # Compute attack surface level
        port_count = len(scan.analysis.open_ports)
        cve_count = len(scan.vulnerabilities)
        if score >= 60 or cve_count >= 5:
            surface = "CRITICAL"
        elif score >= 30 or cve_count >= 2:
            surface = "HIGH"
        elif score >= 10 or port_count >= 5:
            surface = "MEDIUM"
        else:
            surface = "LOW"

        return CorrelationResult(
            risk_score=score,
            attack_surface=surface,
            correlations=correlations,
        )
