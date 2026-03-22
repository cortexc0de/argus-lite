"""Risk scoring engine."""

from __future__ import annotations

from argus_lite.models.risk import RiskSummary
from argus_lite.models.scan import ScanResult

# Severity weights
_SEVERITY_WEIGHTS = {"INFO": 1, "LOW": 3}

# Penalties
_MISSING_HEADER_PENALTY = 3
_WEAK_SSL_PENALTY = 10
_EXPIRED_SSL_PENALTY = 15


def score_scan(scan: ScanResult) -> RiskSummary:
    """Compute risk score for a scan result."""
    breakdown: dict[str, int] = {}

    # Finding scores
    finding_score = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in scan.findings)
    if finding_score:
        breakdown["findings"] = finding_score

    # Missing security headers
    header_score = 0
    sh = scan.analysis.security_headers
    if sh:
        header_score = len(sh.missing_headers) * _MISSING_HEADER_PENALTY
    if header_score:
        breakdown["headers"] = header_score

    # SSL issues
    ssl_score = 0
    ssl = scan.analysis.ssl_info
    if ssl:
        if ssl.weak_cipher:
            ssl_score += _WEAK_SSL_PENALTY
        if ssl.expired:
            ssl_score += _EXPIRED_SSL_PENALTY
    if ssl_score:
        breakdown["ssl"] = ssl_score

    overall = sum(breakdown.values())
    level = _compute_risk_level(overall)

    return RiskSummary(overall_score=overall, risk_level=level, breakdown=breakdown)


def _compute_risk_level(score: int) -> str:
    """Map numeric score to risk level."""
    if score == 0:
        return "NONE"
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    return "HIGH"
