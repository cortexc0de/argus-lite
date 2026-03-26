"""TDD: Tests for Pattern Learning Memory."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestAttackPatterns:
    def test_extract_patterns_from_payloads(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory

        mem = AgentMemory(path=tmp_path / "mem.json")
        mem.record_target_pattern("site1.com", ["WordPress"], [80, 443])
        mem.record_success("site1.com", "<script>alert(1)</script>", "xss")
        mem.record_success("site1.com", "' OR 1=1--", "sqli")
        mem.record_target_pattern("site2.com", ["WordPress"], [80])
        mem.record_success("site2.com", "<img onerror=alert(1)>", "xss")

        patterns = mem.extract_patterns()
        # WordPress → XSS should appear with count=2
        wp_patterns = [p for p in patterns if p["tech"] == "wordpress"]
        xss_patterns = [p for p in wp_patterns if p["vuln_type"] == "xss"]
        assert len(xss_patterns) >= 1
        assert xss_patterns[0]["success_count"] >= 2

    def test_suggest_attacks_for_tech(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory

        mem = AgentMemory(path=tmp_path / "mem.json")
        mem.record_target_pattern("s1.com", ["Laravel"], [443])
        mem.record_success("s1.com", "payload1", "sqli")
        mem.record_success("s1.com", "payload2", "sqli")
        mem.record_success("s1.com", "payload3", "xss")

        suggestions = mem.suggest_attacks(["Laravel"])
        assert "sqli" in suggestions  # more successes
        assert suggestions.index("sqli") < suggestions.index("xss")  # sqli ranked higher

    def test_no_patterns_returns_empty(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory
        mem = AgentMemory(path=tmp_path / "mem.json")
        assert mem.extract_patterns() == []
        assert mem.suggest_attacks(["React"]) == []

    def test_patterns_persist(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory

        mem = AgentMemory(path=tmp_path / "mem.json")
        mem.record_target_pattern("s1.com", ["Django"], [8000])
        mem.record_success("s1.com", "test", "xss")
        mem.save()

        mem2 = AgentMemory(path=tmp_path / "mem.json")
        mem2.load()
        patterns = mem2.extract_patterns()
        assert len(patterns) >= 1
