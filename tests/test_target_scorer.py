"""TDD: Tests for Target Value Scorer."""

import pytest


class TestTargetScorer:
    def test_admin_is_critical(self):
        from argus_lite.core.target_scorer import TargetScorer
        scored = TargetScorer.rule_score("https://example.com/admin")
        assert scored.value == "critical"

    def test_api_with_id_is_high(self):
        from argus_lite.core.target_scorer import TargetScorer
        scored = TargetScorer.rule_score("https://example.com/api/user?id=123")
        assert scored.value == "high"
        assert "IDOR" in scored.vulns_to_test

    def test_static_is_skip(self):
        from argus_lite.core.target_scorer import TargetScorer
        scored = TargetScorer.rule_score("https://example.com/static/style.css")
        assert scored.value == "skip"

    def test_redirect_is_high(self):
        from argus_lite.core.target_scorer import TargetScorer
        scored = TargetScorer.rule_score("https://example.com/redirect?url=http://evil.com")
        assert scored.value == "high"
        assert "SSRF" in scored.vulns_to_test

    def test_score_endpoints_sorted(self):
        from argus_lite.core.target_scorer import TargetScorer
        urls = [
            "https://example.com/static/img.png",
            "https://example.com/admin",
            "https://example.com/api/user?id=1",
            "https://example.com/about",
        ]
        scored = TargetScorer.score_endpoints(urls)
        assert scored[0].value == "critical"
        assert scored[-1].value in ("low", "skip")

    def test_graphql_is_high(self):
        from argus_lite.core.target_scorer import TargetScorer
        scored = TargetScorer.rule_score("https://example.com/graphql")
        assert scored.value == "high"
