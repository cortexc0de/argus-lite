"""TDD: Tests for Meta-Learning."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_lite.core.meta_learning import MetaLearner, SkillOutcome


class TestMetaLearner:
    def test_record_and_priority(self):
        ml = MetaLearner(path=Path("/tmp/test_meta.json"))
        ml.record(SkillOutcome(skill="scan_xss", tech="WordPress", success=True, findings_count=2))
        ml.record(SkillOutcome(skill="scan_xss", tech="WordPress", success=True, findings_count=1))
        ml.record(SkillOutcome(skill="scan_xss", tech="WordPress", success=False))

        priority = ml.get_skill_priority("scan_xss", "WordPress")
        assert priority > 0.5  # 2/3 success

    def test_unknown_returns_default(self):
        ml = MetaLearner()
        assert ml.get_skill_priority("unknown_skill", "unknown_tech") == 0.5

    def test_rank_skills(self):
        ml = MetaLearner()
        for _ in range(5):
            ml.record(SkillOutcome(skill="scan_sqli", tech="php", success=True))
        for _ in range(5):
            ml.record(SkillOutcome(skill="scan_xss", tech="php", success=False))

        ranked = ml.rank_skills(["scan_xss", "scan_sqli"], tech="php")
        assert ranked[0][0] == "scan_sqli"  # higher success rate

    def test_suggest_optimizations(self):
        ml = MetaLearner()
        for _ in range(5):
            ml.record(SkillOutcome(skill="fuzz_paths", tech="nginx", success=False))
        for _ in range(5):
            ml.record(SkillOutcome(skill="scan_nuclei", tech="nginx", success=True, findings_count=3))

        suggestions = ml.suggest_optimizations()
        assert any("Deprioritize" in s and "fuzz_paths" in s for s in suggestions)
        assert any("Prioritize" in s and "scan_nuclei" in s for s in suggestions)

    def test_save_and_load(self, tmp_path):
        ml = MetaLearner(path=tmp_path / "meta.json")
        ml.record(SkillOutcome(skill="check_headers", tech="apache", success=True))
        ml.save()

        ml2 = MetaLearner(path=tmp_path / "meta.json")
        ml2.load()
        assert ml2.get_skill_priority("check_headers", "apache") >= 0.5

    def test_to_llm_context(self):
        ml = MetaLearner()
        ml.record(SkillOutcome(skill="scan_xss", tech="react", success=True))
        ml.record(SkillOutcome(skill="scan_xss", tech="react", success=True))
        ml.record(SkillOutcome(skill="scan_xss", tech="react", success=False))

        ctx = ml.to_llm_context(["React"])
        assert "scan_xss" in ctx
        assert "%" in ctx
