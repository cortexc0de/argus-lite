"""TDD: Tests for AI analysis models."""

import pytest
from pydantic import ValidationError


class TestAIModels:
    def test_attack_chain(self):
        from argus_lite.models.ai import AttackChain

        c = AttackChain(name="Admin via .git", steps=["Found .git", "Extract creds"], severity="HIGH", likelihood="MEDIUM")
        assert c.name == "Admin via .git"
        assert len(c.steps) == 2

    def test_prioritized_finding(self):
        from argus_lite.models.ai import PrioritizedFinding

        p = PrioritizedFinding(original_id="f-001", new_priority=1, reason="Easy to exploit", exploitability="EASY")
        assert p.new_priority == 1

    def test_ai_analysis_defaults(self):
        from argus_lite.models.ai import AIAnalysis

        a = AIAnalysis()
        assert a.executive_summary == ""
        assert a.attack_chains == []
        assert a.recommendations == []
        assert a.tokens_used == 0

    def test_ai_analysis_full(self):
        from argus_lite.models.ai import AIAnalysis, AttackChain, PrioritizedFinding

        a = AIAnalysis(
            executive_summary="Target has moderate risk.",
            attack_chains=[AttackChain(name="Chain1", steps=["Step1"], severity="HIGH", likelihood="LOW")],
            prioritized_findings=[PrioritizedFinding(original_id="f1", new_priority=1, reason="R", exploitability="EASY")],
            recommendations=["Update WordPress", "Add CSP header"],
            trend_analysis="New subdomain discovered since last scan.",
            model_used="gpt-4o",
            tokens_used=1500,
        )
        assert len(a.attack_chains) == 1
        assert len(a.recommendations) == 2

    def test_ai_analysis_json_roundtrip(self):
        from argus_lite.models.ai import AIAnalysis

        a = AIAnalysis(executive_summary="Test", model_used="test-model")
        j = a.model_dump_json()
        a2 = AIAnalysis.model_validate_json(j)
        assert a2.executive_summary == "Test"

    def test_scan_result_with_ai(self):
        from datetime import datetime, timezone
        from argus_lite.models.ai import AIAnalysis
        from argus_lite.models.scan import ScanResult

        r = ScanResult(
            scan_id="t", target="t.com", target_type="domain",
            status="completed", started_at=datetime.now(tz=timezone.utc),
            ai_analysis=AIAnalysis(executive_summary="Safe target."),
        )
        assert r.ai_analysis.executive_summary == "Safe target."

    def test_scan_result_without_ai(self):
        from datetime import datetime, timezone
        from argus_lite.models.scan import ScanResult

        r = ScanResult(
            scan_id="t", target="t.com", target_type="domain",
            status="completed", started_at=datetime.now(tz=timezone.utc),
        )
        assert r.ai_analysis is None


class TestAIConfig:
    def test_default_config(self):
        from argus_lite.core.config import AppConfig

        c = AppConfig()
        assert c.ai.enabled is False
        assert "openai" in c.ai.base_url
        assert c.ai.model == "gpt-4o"
        assert c.ai.api_key == ""

    def test_env_override(self, monkeypatch):
        from argus_lite.core.config import load_config
        from pathlib import Path

        monkeypatch.setenv("ARGUS_AI_KEY", "sk-test123")
        monkeypatch.setenv("ARGUS_AI_URL", "http://localhost:11434/v1")
        monkeypatch.setenv("ARGUS_AI_MODEL", "llama3")

        c = load_config(Path("/tmp/nonexistent.yaml"))
        assert c.ai.api_key == "sk-test123"
        assert c.ai.base_url == "http://localhost:11434/v1"
        assert c.ai.model == "llama3"
