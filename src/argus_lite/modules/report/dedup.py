"""Finding deduplication and summary statistics."""

from __future__ import annotations

from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by title, keeping the first occurrence."""
    seen_titles: set[str] = set()
    result: list[Finding] = []

    for f in findings:
        key = f.title.lower()
        if key not in seen_titles:
            seen_titles.add(key)
            result.append(f)

    return result


def compute_summary(scan: ScanResult) -> dict[str, int | float]:
    """Compute summary statistics from a ScanResult."""
    duration = 0.0
    if scan.completed_at and scan.started_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()

    info_count = sum(1 for f in scan.findings if f.severity == "INFO")
    low_count = sum(1 for f in scan.findings if f.severity == "LOW")

    return {
        "dns_records": len(scan.recon.dns_records),
        "subdomains": len(scan.recon.subdomains),
        "open_ports": len(scan.analysis.open_ports),
        "technologies": len(scan.analysis.technologies),
        "findings": len(scan.findings),
        "info_count": info_count,
        "low_count": low_count,
        "nuclei_findings": len(scan.analysis.nuclei_findings),
        "duration_seconds": duration,
    }
