"""TDD: Tests for Goal Hierarchy Engine."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from argus_lite.core.goal_engine import Goal, GoalHierarchy


class TestGoalModel:
    def test_goal_creation(self):
        g = Goal(id="g1", description="Find IDOR")
        assert g.status == "pending"
        assert g.priority == 0.5

    def test_goal_with_subgoals(self):
        sg = Goal(id="sg1", description="Test /api/user", parent_id="g1")
        g = Goal(id="g1", description="Find IDOR", subgoals=[sg])
        assert len(g.subgoals) == 1


class TestGoalHierarchy:
    def _make_hierarchy(self):
        return GoalHierarchy(
            mission="data_exfiltration",
            root=Goal(id="root", description="Get data", priority=1.0, subgoals=[
                Goal(id="auth", description="Bypass auth", priority=0.8, parent_id="root", subgoals=[
                    Goal(id="idor", description="Find IDOR", priority=0.9, parent_id="auth"),
                    Goal(id="sqli", description="Test SQLi", priority=0.7, parent_id="auth"),
                ]),
                Goal(id="lfi", description="Find LFI", priority=0.5, parent_id="root"),
            ]),
        )

    def test_get_next_goal_highest_priority(self):
        h = self._make_hierarchy()
        g = h.get_next_goal()
        assert g is not None
        assert g.id == "idor"  # highest priority leaf

    def test_get_next_skips_achieved(self):
        h = self._make_hierarchy()
        h.mark_achieved("idor")
        g = h.get_next_goal()
        assert g.id == "sqli"

    def test_mark_achieved_cascades(self):
        h = self._make_hierarchy()
        h.mark_achieved("idor")
        h.mark_achieved("sqli")
        # Both subgoals achieved → parent "auth" should auto-achieve
        assert "auth" in h.achieved_goals

    def test_mark_failed(self):
        h = self._make_hierarchy()
        h.mark_failed("lfi")
        assert h.root.subgoals[1].status == "failed"

    def test_to_llm_context(self):
        h = self._make_hierarchy()
        ctx = h.to_llm_context()
        assert "data_exfiltration" in ctx
        assert "Bypass auth" in ctx

    def test_all_achieved_returns_none(self):
        h = GoalHierarchy(
            mission="test",
            root=Goal(id="r", description="done", status="achieved"),
        )
        assert h.get_next_goal() is None


class TestMissionTemplates:
    def test_missions_exist(self):
        from argus_lite.core.goal_engine import MISSIONS
        assert "data_exfiltration" in MISSIONS
        assert "admin_access" in MISSIONS
        assert "rce" in MISSIONS
        assert "full_assessment" in MISSIONS

    def test_create_hierarchy_fallback(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.config import AIConfig
        from argus_lite.core.goal_engine import create_goal_hierarchy

        config = AIConfig(api_key="test")
        ctx = AgentContext(target="example.com")

        async def mock_llm(*args, **kwargs):
            return {"error": "no api"}

        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, side_effect=mock_llm):
            h = asyncio.get_event_loop().run_until_complete(
                create_goal_hierarchy(config, ctx, mission="data_exfiltration")
            )
        assert h.root.description == "Gain access to sensitive data (database, files, credentials)"
        assert len(h.root.subgoals) > 0
