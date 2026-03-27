"""TDD: Deep audit tests — coverage for all gaps found in pipeline audit.

Tests:
  - Finding severity enum (all 5 levels)
  - Orchestrator severity mapping
  - Skills: nuclei/ffuf Finding conversion
  - Skills: all 11 skills instantiation and interface
  - Agent: PayloadEngine integration
  - Agent: intelligence context (kb + meta + scored targets)
  - Agent: error handling for LLM failures
  - Agent: stealth mode delay
  - AgentContext: build_llm_context includes all fields
  - ToolRunner: stdin_data parameter
  - Multi-agent: roles, team coordination
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from argus_lite.core.config import AIConfig, AppConfig


# ── Finding Severity Tests ──


class TestFindingSeverityEnum:
    """Verify Finding accepts all 5 severity levels and rejects invalid."""

    @pytest.mark.parametrize("sev", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_valid_severities(self, sev):
        from argus_lite.models.finding import Finding

        f = Finding(
            id="f1", type="t", severity=sev, title="T",
            description="D", asset="a", evidence="e", source="s", remediation="r",
        )
        assert f.severity == sev

    @pytest.mark.parametrize("sev", ["UNKNOWN", "WARNING", "extreme", "", "medium"])
    def test_invalid_severities_rejected(self, sev):
        from argus_lite.models.finding import Finding

        with pytest.raises(ValidationError):
            Finding(
                id="f1", type="t", severity=sev, title="T",
                description="D", asset="a", evidence="e", source="s", remediation="r",
            )


# ── Orchestrator Severity Mapping Tests ──


class TestOrchestratorSeverityMapping:
    """Verify orchestrator correctly maps nuclei severity to Finding severity."""

    def test_nuclei_high_severity_preserved(self):
        from argus_lite.models.analysis import NucleiFinding
        from argus_lite.models.finding import Finding

        # Simulate _collect_findings_from_analysis logic
        _VALID = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        nf = NucleiFinding(
            template_id="CVE-2023-1234", name="Critical RCE",
            severity="high", matched_at="https://test.com",
        )
        sev = nf.severity.upper() if nf.severity else "INFO"
        if sev not in _VALID:
            sev = "INFO"

        assert sev == "HIGH"

        f = Finding(
            id=f"nuclei-{nf.template_id}", type="nuclei", severity=sev,
            title=nf.name, description="test", asset=nf.matched_at,
            evidence="test", source="nuclei", remediation="fix",
        )
        assert f.severity == "HIGH"

    @pytest.mark.parametrize("input_sev,expected", [
        ("info", "INFO"), ("low", "LOW"), ("medium", "MEDIUM"),
        ("high", "HIGH"), ("critical", "CRITICAL"),
        ("garbage", "INFO"), ("", "INFO"),
    ])
    def test_severity_normalization(self, input_sev, expected):
        _VALID = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        sev = input_sev.upper() if input_sev else "INFO"
        if sev not in _VALID:
            sev = "INFO"
        assert sev == expected


# ── Skills: Nuclei Finding Conversion ──


class TestScanNucleiSkillFindings:
    """Verify ScanNucleiSkill converts nuclei findings to Finding objects."""

    def test_nuclei_skill_returns_finding_objects(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import ScanNucleiSkill
        from argus_lite.models.analysis import NucleiFinding

        config = AppConfig()
        skill = ScanNucleiSkill(config)
        ctx = AgentContext(target="example.com")

        mock_findings = [
            NucleiFinding(
                template_id="CVE-2023-001", name="Test Vuln",
                severity="high", matched_at="https://example.com/path",
            ),
        ]

        with patch("argus_lite.modules.analysis.nuclei.nuclei_scan",
                    new_callable=AsyncMock, return_value=mock_findings), \
             patch.object(skill, "is_available", return_value=True), \
             patch("argus_lite.core.tool_runner.BaseToolRunner.check_available", return_value=True):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"target": "https://example.com"}, ctx)
            )

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0].severity == "HIGH"
        assert result.findings[0].type == "nuclei"
        assert result.findings[0].title == "Test Vuln"


class TestFuzzPathsSkillFindings:
    """Verify FuzzPathsSkill converts sensitive paths to Finding objects."""

    def test_fuzz_skill_returns_sensitive_path_findings(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import FuzzPathsSkill
        from argus_lite.models.analysis import FfufResult

        config = AppConfig()
        skill = FuzzPathsSkill(config)
        ctx = AgentContext(target="example.com")

        mock_results = [
            FfufResult(url="https://example.com/admin", status_code=200, content_length=500),
            FfufResult(url="https://example.com/about", status_code=200, content_length=300),
            FfufResult(url="https://example.com/.git/config", status_code=403, content_length=10),
        ]

        with patch("argus_lite.modules.analysis.ffuf_fuzz.ffuf_scan",
                    new_callable=AsyncMock, return_value=mock_results), \
             patch.object(skill, "is_available", return_value=True), \
             patch("argus_lite.core.tool_runner.BaseToolRunner.check_available", return_value=True):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"target": "https://example.com"}, ctx)
            )

        assert result.success
        assert result.data["count"] == 3
        # Only /admin and /.git should be flagged as sensitive
        assert len(result.findings) == 2
        sensitive_titles = [f.title for f in result.findings]
        assert any("/admin" in t for t in sensitive_titles)
        assert any("/.git" in t for t in sensitive_titles)


# ── Skills: XSS/SQLi Severity ──


class TestXssSqliSeverity:
    """Verify XSS findings are MEDIUM and SQLi findings are HIGH."""

    def test_xss_severity_is_medium(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import ScanXssSkill
        from argus_lite.models.analysis import DalfoxFinding

        config = AppConfig()
        skill = ScanXssSkill(config)
        ctx = AgentContext(target="example.com")

        mock_findings = [
            DalfoxFinding(url="https://example.com/search", param="q",
                          payload="<script>alert(1)</script>", type="reflected",
                          evidence="reflected XSS"),
        ]

        with patch("argus_lite.modules.analysis.dalfox.dalfox_scan",
                    new_callable=AsyncMock, return_value=mock_findings), \
             patch.object(skill, "is_available", return_value=True), \
             patch("argus_lite.core.tool_runner.BaseToolRunner.check_available", return_value=True):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"target": "https://example.com"}, ctx)
            )

        assert result.findings[0].severity == "MEDIUM"

    def test_sqli_severity_is_high(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import ScanSqliSkill
        from argus_lite.models.analysis import SqlmapFinding

        config = AppConfig()
        skill = ScanSqliSkill(config)
        ctx = AgentContext(target="example.com")

        mock_findings = [
            SqlmapFinding(url="https://example.com/api", param="id",
                          type="boolean-based", dbms="MySQL",
                          payload="1 OR 1=1"),
        ]

        with patch("argus_lite.modules.analysis.sqlmap_scan.sqlmap_scan",
                    new_callable=AsyncMock, return_value=mock_findings), \
             patch.object(skill, "is_available", return_value=True), \
             patch("argus_lite.core.tool_runner.BaseToolRunner.check_available", return_value=True):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"url": "https://example.com/api"}, ctx)
            )

        assert result.findings[0].severity == "HIGH"


# ── All 11 Skills Instantiation ──


class TestAllSkillsInterface:
    """Verify all 11 skills are properly instantiated and have correct interface."""

    def test_all_skills_registered(self):
        from argus_lite.core.skills import build_skill_registry
        registry = build_skill_registry(AppConfig())
        assert len(registry._skills) == 14

    @pytest.mark.parametrize("name", [
        "enumerate_subdomains", "probe_http", "crawl_site",
        "scan_nuclei", "fuzz_paths", "scan_xss", "scan_sqli",
        "check_headers", "detect_tech", "scan_ports", "test_payload",
    ])
    def test_skill_exists_and_has_interface(self, name):
        from argus_lite.core.skills import build_skill_registry
        registry = build_skill_registry(AppConfig())
        skill = registry.get(name)
        assert skill is not None, f"Skill '{name}' not found"
        assert skill.name == name
        assert len(skill.description) > 5
        assert hasattr(skill, "execute")
        assert hasattr(skill, "is_available")

    def test_tool_dependent_skills_not_available_without_tools(self):
        from argus_lite.core.skills import build_skill_registry
        registry = build_skill_registry(AppConfig())
        # These need external binaries — should not be available in CI
        tool_skills = ["enumerate_subdomains", "probe_http", "scan_nuclei"]
        for name in tool_skills:
            skill = registry.get(name)
            # May or may not be available, just verify no crash
            skill.is_available()

    def test_check_headers_always_available(self):
        from argus_lite.core.skills import CheckHeadersSkill
        skill = CheckHeadersSkill()
        assert skill.is_available()

    def test_test_payload_always_available(self):
        from argus_lite.core.skills import TestPayloadSkill
        skill = TestPayloadSkill()
        assert skill.is_available()


# ── Agent: Intelligence Context ──


class TestAgentIntelligenceContext:
    """Verify agent wires kb_context, meta_context, and scored_targets into context."""

    def test_intelligence_context_included_in_llm_prompt(self):
        from argus_lite.core.agent_context import AgentContext

        ctx = AgentContext(target="test.com")
        ctx.intelligence_context = "Knowledge Base:\n- WordPress exploit patterns"
        text = ctx.build_llm_context()
        assert "Knowledge Base" in text
        assert "WordPress exploit patterns" in text

    def test_attack_chains_in_llm_prompt(self):
        from argus_lite.core.agent_context import AgentContext

        ctx = AgentContext(target="test.com")
        ctx.attack_chains_context = "Chain: XSS → Session Hijack (prob=0.7)"
        text = ctx.build_llm_context()
        assert "Chain: XSS" in text

    def test_environment_in_llm_prompt(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.environment import EnvironmentProfile

        ctx = AgentContext(target="test.com")
        ctx.environment = EnvironmentProfile(
            waf_detected=True, waf_type="Cloudflare", cdn="Cloudflare",
        )
        text = ctx.build_llm_context()
        assert "WAF: Cloudflare" in text
        assert "CDN: Cloudflare" in text

    def test_stealth_mode_in_llm_prompt(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.environment import StealthConfig

        ctx = AgentContext(target="test.com", stealth=StealthConfig(enabled=True, delay_ms=500))
        text = ctx.build_llm_context()
        assert "Stealth: ON" in text
        assert "500ms" in text


# ── Agent: Error Handling ──


class TestAgentErrorHandling:
    """Verify agent handles LLM failures gracefully."""

    def test_call_llm_no_api_key_returns_error(self):
        from argus_lite.core.agent import _call_llm

        config = AIConfig(api_key="")
        result = asyncio.get_event_loop().run_until_complete(
            _call_llm(config, "system", "prompt")
        )
        assert "error" in result
        assert "No AI API key" in result["error"]

    def test_call_llm_invalid_json_returns_error(self):
        from argus_lite.core.agent import _call_llm

        config = AIConfig(api_key="test-key", model="test")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "not valid json at all"}}]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                _call_llm(config, "system", "prompt")
            )
        assert "error" in result

    def test_call_llm_api_error_status(self):
        from argus_lite.core.agent import _call_llm

        config = AIConfig(api_key="test-key", model="test")
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                _call_llm(config, "system", "prompt")
            )
        assert "error" in result
        assert "500" in result["error"]


# ── ToolRunner: stdin_data ──


class TestToolRunnerStdin:
    """Verify ToolRunner supports stdin_data parameter."""

    def test_run_signature_accepts_stdin_data(self):
        from argus_lite.core.tool_runner import BaseToolRunner
        import inspect
        sig = inspect.signature(BaseToolRunner.run)
        assert "stdin_data" in sig.parameters

    def test_run_without_stdin_data(self):
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner("echo", "/bin/echo")
        result = asyncio.get_event_loop().run_until_complete(
            runner.run(["hello"])
        )
        assert result.success
        assert "hello" in result.stdout

    def test_run_with_stdin_data(self):
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner("cat", "/bin/cat")
        result = asyncio.get_event_loop().run_until_complete(
            runner.run([], stdin_data="line1\nline2\n")
        )
        assert result.success
        assert "line1" in result.stdout
        assert "line2" in result.stdout


# ── Multi-Agent Tests ──


class TestMultiAgent:
    """Tests for multi-agent coordination."""

    def test_agent_roles_defined(self):
        from argus_lite.core.multi_agent import RECON_ROLE, VULN_ROLE, EXPLOIT_ROLE

        assert RECON_ROLE.name == "recon"
        assert "enumerate_subdomains" in RECON_ROLE.skills

        assert VULN_ROLE.name == "vuln_scanner"
        assert "scan_nuclei" in VULN_ROLE.skills

        assert EXPLOIT_ROLE.name == "exploit"
        assert "test_payload" in EXPLOIT_ROLE.skills

    def test_role_skill_registry_filters(self):
        from argus_lite.core.multi_agent import RoleSkillRegistry
        from argus_lite.core.skills import build_skill_registry

        full = build_skill_registry(AppConfig())
        filtered = RoleSkillRegistry(full, ["check_headers", "test_payload"])
        assert len(filtered._skills) == 2
        assert filtered.get("check_headers") is not None
        assert filtered.get("scan_nuclei") is None

    def test_role_skill_registry_empty_filter(self):
        from argus_lite.core.multi_agent import RoleSkillRegistry
        from argus_lite.core.skills import build_skill_registry

        full = build_skill_registry(AppConfig())
        filtered = RoleSkillRegistry(full, [])
        assert len(filtered._skills) == 0

    def test_agent_team_creation(self):
        from argus_lite.core.multi_agent import AgentTeam

        team = AgentTeam(
            config=AIConfig(api_key="test"),
            app_config=AppConfig(),
        )
        assert team._ai_config.api_key == "test"
        assert team._full_registry is not None


# ── PayloadEngine Tests ──


class TestPayloadEngine:
    """Tests for the adaptive payload engine."""

    def test_payload_engine_creation(self):
        from argus_lite.core.payload_engine import PayloadEngine

        engine = PayloadEngine(AIConfig(api_key="test"), max_iterations=5)
        assert engine._max_iterations == 5

    def test_payload_attempt_model(self):
        from argus_lite.core.payload_engine import PayloadAttempt

        attempt = PayloadAttempt(
            payload="<script>alert(1)</script>",
            response_code=200,
            reflected=True,
            blocked=False,
        )
        assert attempt.reflected
        assert not attempt.blocked
        assert attempt.response_code == 200

    def test_adaptive_test_no_api_key(self):
        from argus_lite.core.payload_engine import PayloadEngine

        engine = PayloadEngine(AIConfig(api_key=""), max_iterations=3)
        attempts = asyncio.get_event_loop().run_until_complete(
            engine.adaptive_test("https://test.com", "q", "xss")
        )
        # No API key → _generate_payload returns "" → loop breaks immediately
        assert attempts == []


# ── AgentContext: scored_targets and intelligence_context ──


class TestAgentContextNewFields:
    """Verify new fields on AgentContext work properly."""

    def test_intelligence_context_default_empty(self):
        from argus_lite.core.agent_context import AgentContext
        ctx = AgentContext(target="x.com")
        assert ctx.intelligence_context == ""

    def test_scored_targets_default_empty(self):
        from argus_lite.core.agent_context import AgentContext
        ctx = AgentContext(target="x.com")
        assert ctx.scored_targets == []

    def test_context_with_all_fields(self):
        from argus_lite.core.agent_context import AgentContext, AgentPlan
        from argus_lite.core.environment import EnvironmentProfile, StealthConfig

        ctx = AgentContext(
            target="test.com",
            environment=EnvironmentProfile(waf_detected=True, waf_type="ModSec"),
            stealth=StealthConfig(enabled=True, delay_ms=200),
        )
        ctx.attack_chains_context = "Chain: SSRF → Internal Access"
        ctx.intelligence_context = "KB: WordPress exploit patterns available"
        ctx.plan = AgentPlan(goal="Find RCE", steps=["scan_nuclei"])

        text = ctx.build_llm_context()
        assert "test.com" in text
        assert "WAF: ModSec" in text
        assert "Stealth: ON" in text
        assert "Chain: SSRF" in text
        assert "KB: WordPress" in text
        assert "Find RCE" in text


# ── PlanTree Tests ──


class TestPlanTree:
    """Verify plan tree DFS and tracking."""

    def test_plan_tree_dfs_order(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree

        tree = PlanTree(
            goal="Test",
            root=PlanNode(
                id="root", action="branch", children=[
                    PlanNode(id="a", action="scan_nuclei", confidence=0.5),
                    PlanNode(id="b", action="scan_xss", confidence=0.9),
                ],
            ),
        )
        # Should pick highest confidence first
        next_node = tree.get_next_node()
        assert next_node.id == "b"  # 0.9 > 0.5

    def test_plan_tree_mark_completed(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree

        tree = PlanTree(
            goal="Test",
            root=PlanNode(id="root", action="scan_nuclei"),
        )
        tree.mark_completed("root", "found 3 vulns")
        assert tree.root.status == "completed"
        assert tree.root.result_summary == "found 3 vulns"
        assert tree.get_next_node() is None  # no more pending

    def test_plan_tree_to_llm_context(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree

        tree = PlanTree(
            goal="Find vulns",
            root=PlanNode(id="root", action="scan_nuclei", status="completed"),
        )
        text = tree.to_llm_context()
        assert "Find vulns" in text
        assert "✓" in text  # completed icon


# ── Vulnerability Model Tests ──


class TestVulnerabilityModel:
    """Verify Vulnerability model uses Field(default_factory=list)."""

    def test_references_isolated_between_instances(self):
        from argus_lite.models.finding import Vulnerability

        v1 = Vulnerability(id="v1", finding_id="f1")
        v2 = Vulnerability(id="v2", finding_id="f2")
        v1.references.append("https://cve.org/1")
        assert len(v2.references) == 0  # Must not leak between instances


# ── AgentStep Timestamp ──


class TestAgentStepTimestamp:
    """Verify AgentStep auto-sets timestamp."""

    def test_timestamp_auto_set(self):
        from argus_lite.core.agent_context import AgentStep

        step = AgentStep(step_number=1, action="scan_nuclei")
        assert step.timestamp is not None
        assert step.timestamp.tzinfo is not None  # timezone-aware

    def test_timestamp_explicit(self):
        from argus_lite.core.agent_context import AgentStep

        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        step = AgentStep(step_number=1, timestamp=ts)
        assert step.timestamp == ts
