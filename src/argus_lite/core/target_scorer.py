"""Target Value Scoring — prioritize endpoints before skill execution."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel


class ScoredTarget(BaseModel):
    """An endpoint scored by attack potential."""

    url: str
    value: str = "medium"        # critical / high / medium / low / skip
    reasons: list[str] = []
    vulns_to_test: list[str] = []


# Patterns that indicate high-value targets
_CRITICAL_PATTERNS = [
    (r"/admin", "critical", "Admin panel", ["auth_bypass", "IDOR"]),
    (r"/wp-admin", "critical", "WordPress admin", ["auth_bypass", "plugin_vuln"]),
    (r"/phpmyadmin", "critical", "Database admin UI", ["auth_bypass", "SQLi"]),
    (r"/api/.*\?.*id=", "high", "API with ID parameter", ["IDOR", "SQLi"]),
    (r"/api/", "high", "API endpoint", ["IDOR", "injection"]),
    (r"\?.*redirect=|\?.*url=|\?.*return=|\?.*next=", "high", "Redirect parameter", ["SSRF", "open_redirect"]),
    (r"\?.*file=|\?.*path=|\?.*include=", "high", "File parameter", ["LFI", "path_traversal"]),
    (r"/auth|/login|/signup|/register|/oauth", "high", "Auth endpoint", ["auth_bypass", "brute_force"]),
    (r"/upload|/import", "high", "Upload endpoint", ["file_upload", "RCE"]),
    (r"/graphql", "high", "GraphQL endpoint", ["introspection", "IDOR"]),
    (r"\?.*q=|\?.*search=|\?.*query=", "medium", "Search parameter", ["XSS", "SQLi"]),
    (r"/static/|/assets/|/css/|/js/|/images/", "skip", "Static asset", []),
    (r"\.(css|js|png|jpg|gif|svg|ico|woff|ttf)$", "skip", "Static file", []),
]


class TargetScorer:
    """Score endpoints by attack value using pattern rules."""

    @staticmethod
    def score_endpoints(urls: list[str]) -> list[ScoredTarget]:
        """Score a list of URLs by attack potential."""
        results = []
        for url in urls:
            scored = TargetScorer.rule_score(url)
            results.append(scored)
        # Sort: critical first, skip last
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "skip": 4}
        results.sort(key=lambda s: order.get(s.value, 2))
        return results

    @staticmethod
    def rule_score(url: str) -> ScoredTarget:
        """Fast rule-based scoring without LLM."""
        url_lower = url.lower()

        for pattern, value, reason, vulns in _CRITICAL_PATTERNS:
            if re.search(pattern, url_lower):
                return ScoredTarget(
                    url=url, value=value, reasons=[reason], vulns_to_test=vulns,
                )

        # Default: check if URL has query parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            return ScoredTarget(
                url=url, value="medium",
                reasons=["Has query parameters"],
                vulns_to_test=["XSS", "SQLi"],
            )

        return ScoredTarget(url=url, value="low", reasons=["No parameters"])
