"""Security headers analysis."""

from __future__ import annotations

from argus_lite.models.analysis import SecurityHeadersResult
from argus_lite.models.finding import Finding
from argus_lite.modules.analysis.headers import parse_curl_headers

# Security headers to check (lowercase)
_SECURITY_HEADERS = {
    "strict-transport-security": ("hsts", "Strict-Transport-Security (HSTS)"),
    "x-frame-options": ("x_frame_options", "X-Frame-Options"),
    "x-content-type-options": ("x_content_type_options", "X-Content-Type-Options"),
    "content-security-policy": ("csp", "Content-Security-Policy (CSP)"),
    "x-xss-protection": ("x_xss_protection", "X-XSS-Protection"),
    "referrer-policy": ("referrer_policy", "Referrer-Policy"),
    "permissions-policy": ("permissions_policy", "Permissions-Policy"),
}


def analyze_security_headers(raw_headers: str) -> SecurityHeadersResult:
    """Analyze raw HTTP headers for security header presence."""
    headers = parse_curl_headers(raw_headers)
    present: dict[str, bool] = {}
    missing: list[str] = []

    for header_name, (field_name, display_name) in _SECURITY_HEADERS.items():
        found = header_name in headers
        present[field_name] = found
        if not found:
            missing.append(header_name)

    return SecurityHeadersResult(
        hsts=present.get("hsts", False),
        x_frame_options=present.get("x_frame_options", False),
        x_content_type_options=present.get("x_content_type_options", False),
        csp=present.get("csp", False),
        x_xss_protection=present.get("x_xss_protection", False),
        referrer_policy=present.get("referrer_policy", False),
        permissions_policy=present.get("permissions_policy", False),
        missing_headers=missing,
    )


def security_headers_findings(raw_headers: str, asset: str) -> list[Finding]:
    """Generate Finding objects for each missing security header."""
    result = analyze_security_headers(raw_headers)
    findings: list[Finding] = []

    _REMEDIATION = {
        "strict-transport-security": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "x-frame-options": "Add header: X-Frame-Options: DENY",
        "x-content-type-options": "Add header: X-Content-Type-Options: nosniff",
        "content-security-policy": "Add header: Content-Security-Policy: default-src 'self'",
        "x-xss-protection": "Add header: X-XSS-Protection: 1; mode=block",
        "referrer-policy": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "permissions-policy": "Add header: Permissions-Policy: camera=(), microphone=()",
    }

    for header_name in result.missing_headers:
        display = _SECURITY_HEADERS.get(header_name, ("", header_name))[1]
        findings.append(
            Finding(
                id=f"missing-header-{header_name}",
                type="missing_header",
                severity="INFO",
                title=f"Missing {display}",
                description=f"The {display} header is not set on {asset}.",
                asset=asset,
                evidence=f"Header '{header_name}' not found in HTTP response",
                source="security_headers",
                remediation=_REMEDIATION.get(header_name, f"Add the {header_name} header"),
            )
        )

    return findings
