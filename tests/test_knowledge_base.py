"""TDD: Tests for Knowledge Base."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestKnowledgeBase:
    def test_builtin_entries(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        assert len(kb._knowledge) >= 6

    def test_query_by_tech(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        results = kb.query(tech="wordpress")
        assert len(results) >= 1
        assert any("csrf" in k.exploit_type for k in results)

    def test_query_graphql(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        results = kb.query(tech="graphql")
        assert any(k.id == "graphql-introspection" for k in results)

    def test_record_outcome_success(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        old_conf = kb._knowledge[0].confidence
        kb.record_outcome(kb._knowledge[0].id, success=True)
        assert kb._knowledge[0].confidence > old_conf

    def test_record_outcome_failure(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        old_conf = kb._knowledge[0].confidence
        kb.record_outcome(kb._knowledge[0].id, success=False)
        assert kb._knowledge[0].confidence < old_conf

    def test_to_llm_context(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        ctx = kb.to_llm_context(["WordPress", "GraphQL"])
        assert "wordpress" in ctx.lower() or "graphql" in ctx.lower()

    def test_save_and_load(self, tmp_path):
        from argus_lite.core.knowledge_base import ExploitKnowledge, KnowledgeBase

        kb = KnowledgeBase(path=tmp_path / "kb.json")
        kb.add_knowledge(ExploitKnowledge(
            id="custom-1", tech="react", conditions=["client-side rendering"],
            exploit_type="xss", exploit_chain=["find input", "inject payload"],
        ))
        kb.save()

        kb2 = KnowledgeBase(path=tmp_path / "kb.json")
        kb2.load()
        custom = [k for k in kb2._knowledge if k.id == "custom-1"]
        assert len(custom) == 1

    def test_empty_tech_returns_general(self):
        from argus_lite.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        results = kb.query(tech="")
        # Should return "any" tech entries (ssrf-redirect, file-upload-rce)
        assert len(results) >= 1
