"""TDD: Tests for Agent v3 — execution loop, planner, context, memory."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AIConfig, AppConfig


def _mock_llm_response(content: dict):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": json.dumps(content)}}]
    }
    return mock_resp


class TestAgentContext:
    def test_creates_with_target(self):
        from argus_lite.core.agent_context import AgentContext
        ctx = AgentContext(target="example.com")
        assert ctx.target == "example.com"
        assert ctx.scan_result is not None

    def test_build_llm_context_includes_target(self):
        from argus_lite.core.agent_context import AgentContext
        ctx = AgentContext(target="test.com")
        text = ctx.build_llm_context()
        assert "test.com" in text

    def test_update_from_result_adds_findings(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import SkillResult
        from argus_lite.models.finding import Finding

        ctx = AgentContext(target="x.com")
        f = Finding(id="f1", type="t", severity="INFO", title="Test",
                    description="d", asset="x", evidence="e", source="s", remediation="r")
        result = SkillResult(success=True, findings=[f], summary="ok")
        ctx.update_from_result("test_skill", result)
        assert len(ctx.scan_result.findings) == 1


class TestAgentPlan:
    def test_plan_creation(self):
        from argus_lite.core.agent_context import AgentPlan
        plan = AgentPlan(goal="Find IDOR", steps=["probe_http", "test_payload"])
        assert plan.goal == "Find IDOR"
        assert len(plan.steps) == 2
        assert plan.current_step == 0

    def test_plan_tracking(self):
        from argus_lite.core.agent_context import AgentPlan
        plan = AgentPlan(goal="Test", steps=["a", "b", "c"])
        plan.completed.append("a")
        plan.failed.append("b")
        remaining = [s for s in plan.steps if s not in plan.completed and s not in plan.failed]
        assert remaining == ["c"]


class TestAgentMemory:
    def test_save_and_load(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory

        mem = AgentMemory(path=tmp_path / "mem.json")
        mem.record_success("example.com", "' OR 1=1", "sqli", "/api")
        mem.record_target_pattern("example.com", ["WordPress"], [80, 443])
        mem.save()

        mem2 = AgentMemory(path=tmp_path / "mem.json")
        mem2.load()
        assert len(mem2.successful_payloads["example.com"]) == 1
        assert mem2.target_patterns["example.com"]["tech_stack"] == ["WordPress"]

    def test_get_context_for_target(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory

        mem = AgentMemory(path=tmp_path / "mem.json")
        mem.record_success("x.com", "payload1", "xss")
        mem.record_target_pattern("x.com", ["React"], [443])

        ctx = mem.get_context_for_target("x.com")
        assert "xss" in ctx
        assert "React" in ctx

    def test_empty_memory_returns_empty_context(self):
        from argus_lite.core.agent_memory import AgentMemory
        mem = AgentMemory(path=Path("/nonexistent"))
        assert mem.get_context_for_target("x.com") == ""

    def test_load_nonexistent_file(self, tmp_path):
        from argus_lite.core.agent_memory import AgentMemory
        mem = AgentMemory(path=tmp_path / "nonexistent.json")
        mem.load()  # should not raise
        assert mem.successful_payloads == {}


class TestAgentPlanner:
    def test_create_plan(self):
        from argus_lite.core.agent import AgentPlanner
        from argus_lite.core.agent_context import AgentContext

        config = AIConfig(api_key="test", model="test")
        planner = AgentPlanner(config)
        ctx = AgentContext(target="example.com")

        expected = {"goal": "Find API vulnerabilities", "steps": ["probe_http", "scan_nuclei"]}
        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, return_value=expected):
            plan = asyncio.get_event_loop().run_until_complete(planner.create_plan(ctx))

        assert plan.goal == "Find API vulnerabilities"
        assert len(plan.steps) == 2

    def test_adapt_plan_after_failure(self):
        from argus_lite.core.agent import AgentPlanner
        from argus_lite.core.agent_context import AgentContext, AgentPlan

        config = AIConfig(api_key="test", model="test")
        planner = AgentPlanner(config)
        ctx = AgentContext(target="example.com")
        ctx.plan = AgentPlan(goal="Test", steps=["scan_xss", "scan_sqli"], completed=["scan_xss"])

        expected = {"goal": "Test — adapted", "steps": ["check_headers", "detect_tech"]}
        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, return_value=expected):
            new_plan = asyncio.get_event_loop().run_until_complete(
                planner.adapt_plan(ctx, "scan_sqli")
            )

        assert "scan_sqli" in new_plan.failed


class TestPentestAgentRun:
    def test_full_loop_executes_skills(self):
        from argus_lite.core.agent import PentestAgent
        from argus_lite.core.skills import Skill, SkillRegistry, SkillResult

        class MockSkill(Skill):
            name = "check_headers"
            description = "test"
            execute_count = 0
            async def execute(self, params, context):
                MockSkill.execute_count += 1
                return SkillResult(success=True, summary="2 missing headers")

        registry = SkillRegistry()
        registry.register(MockSkill())

        config = AIConfig(api_key="test", model="test")
        agent = PentestAgent(config, skill_registry=registry, max_steps=3)

        # Responses: 1=planner create_plan, 2=decide (check_headers), 3=decide (done)
        responses = [
            {"goal": "test headers", "steps": ["check_headers"]},
            {"thought": "checking headers", "action": "check_headers", "input": {}},
            {"thought": "done", "action": "done", "input": {}, "report": "Complete"},
        ]
        call_idx = [0]

        async def mock_call_llm(*args, **kwargs):
            idx = min(call_idx[0], len(responses) - 1)
            call_idx[0] += 1
            return responses[idx]

        async def mock_orch_run(self):
            from argus_lite.models.scan import ScanResult
            return ScanResult(scan_id="t", target="example.com", target_type="domain",
                              status="completed", started_at=datetime.now(tz=timezone.utc))

        MockSkill.execute_count = 0

        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, side_effect=mock_call_llm), \
             patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_orch_run):
            result = asyncio.get_event_loop().run_until_complete(
                agent.run("example.com", AppConfig())
            )

        assert result.target == "example.com"
        assert MockSkill.execute_count >= 1  # skill was actually EXECUTED
        assert "check_headers" in result.skills_used

    def test_backward_compat_classify(self):
        from argus_lite.core.agent import PentestAgent

        config = AIConfig(api_key="test", model="test")
        agent = PentestAgent(config)

        expected = {"endpoints": [{"url": "/test", "priority": "high"}]}
        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, return_value=expected):
            result = asyncio.get_event_loop().run_until_complete(
                agent.classify_endpoints(["/test"], ["PHP"])
            )
        assert "endpoints" in result

    def test_backward_compat_record_step(self):
        from argus_lite.core.agent import PentestAgent

        config = AIConfig(api_key="test")
        agent = PentestAgent(config)
        agent.record_step({"action": "test"}, "ok")
        assert len(agent._history) == 1

    def test_no_api_key_returns_error(self):
        from argus_lite.core.agent import PentestAgent

        config = AIConfig(api_key="")
        agent = PentestAgent(config)
        result = asyncio.get_event_loop().run_until_complete(
            agent.classify_endpoints([], [])
        )
        assert "error" in result
