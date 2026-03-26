"""Multi-Agent Coordination — specialized agents working together."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

from argus_lite.core.agent_context import AgentResult, AgentStep
from argus_lite.core.config import AIConfig, AppConfig
from argus_lite.core.skills import SkillRegistry, build_skill_registry

logger = logging.getLogger(__name__)


class AgentRole(BaseModel):
    """Definition of a specialized agent role."""

    name: str
    description: str
    skills: list[str]
    system_prompt_extra: str = ""


# Pre-defined roles
RECON_ROLE = AgentRole(
    name="recon",
    description="Reconnaissance specialist — discovers subdomains, probes services, identifies technologies",
    skills=["enumerate_subdomains", "probe_http", "crawl_site", "detect_tech", "scan_ports"],
    system_prompt_extra="Focus ONLY on reconnaissance. Discover as much as possible about the target's attack surface. Do NOT attempt exploitation.",
)

VULN_ROLE = AgentRole(
    name="vuln_scanner",
    description="Vulnerability scanner — finds known vulns, misconfigs, missing headers",
    skills=["scan_nuclei", "check_headers", "fuzz_paths"],
    system_prompt_extra="Focus on finding vulnerabilities using templates and fuzzing. Report findings clearly. Do NOT attempt exploitation.",
)

EXPLOIT_ROLE = AgentRole(
    name="exploit",
    description="Exploit specialist — tests XSS, SQLi, sends custom payloads",
    skills=["scan_xss", "scan_sqli", "test_payload"],
    system_prompt_extra="You are an exploit specialist. Test high-value targets for XSS and SQL injection. Use test_payload for custom attacks. Be precise and efficient.",
)


class RoleSkillRegistry(SkillRegistry):
    """SkillRegistry filtered to a specific role's allowed skills."""

    def __init__(self, full_registry: SkillRegistry, allowed_skills: list[str]) -> None:
        super().__init__()
        for name, skill in full_registry._skills.items():
            if name in allowed_skills:
                self._skills[name] = skill


class AgentTeam:
    """Coordinate multiple specialized agents for deeper analysis."""

    def __init__(self, config: AIConfig, app_config: AppConfig) -> None:
        self._ai_config = config
        self._app_config = app_config
        self._full_registry = build_skill_registry(app_config)

    async def run(self, target: str, max_steps_per_agent: int = 5) -> AgentResult:
        """Run multi-agent pipeline: Recon → Vuln Scanner → Exploit."""
        from argus_lite.core.agent import PentestAgent
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.agent_memory import AgentMemory
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.risk_scorer import score_scan

        memory = AgentMemory()
        memory.load()

        all_steps: list[AgentStep] = []
        all_skills: list[str] = []

        # Phase 1: Quick recon via orchestrator
        logger.info("Multi-agent: Phase 1 — base recon")
        orch = ScanOrchestrator(target=target, config=self._app_config, preset="quick", skip_cve=True)
        scan_result = await orch.run()
        scan_result.risk_summary = score_scan(scan_result)

        # Phase 2: Recon Agent — deep reconnaissance
        logger.info("Multi-agent: Phase 2 — recon agent")
        recon_registry = RoleSkillRegistry(self._full_registry, RECON_ROLE.skills)
        recon_agent = PentestAgent(
            self._ai_config, skill_registry=recon_registry, max_steps=max_steps_per_agent,
        )
        # Inject recon agent's extra prompt context
        recon_context = AgentContext(target=target, scan_result=scan_result,
                                     skill_registry=recon_registry, memory=memory)
        recon_result = await self._run_role_agent(recon_agent, recon_context, RECON_ROLE)
        all_steps.extend(recon_result.steps)
        all_skills.extend(recon_result.skills_used)

        # Phase 3: Vuln Scanner Agent
        logger.info("Multi-agent: Phase 3 — vuln scanner agent")
        vuln_registry = RoleSkillRegistry(self._full_registry, VULN_ROLE.skills)
        vuln_agent = PentestAgent(
            self._ai_config, skill_registry=vuln_registry, max_steps=max_steps_per_agent,
        )
        vuln_context = AgentContext(target=target, scan_result=recon_context.scan_result,
                                    skill_registry=vuln_registry, memory=memory)
        vuln_result = await self._run_role_agent(vuln_agent, vuln_context, VULN_ROLE)
        all_steps.extend(vuln_result.steps)
        all_skills.extend(vuln_result.skills_used)

        # Phase 4: Exploit Agent — test high-value findings
        logger.info("Multi-agent: Phase 4 — exploit agent")
        exploit_registry = RoleSkillRegistry(self._full_registry, EXPLOIT_ROLE.skills)
        exploit_agent = PentestAgent(
            self._ai_config, skill_registry=exploit_registry, max_steps=max_steps_per_agent,
        )
        exploit_context = AgentContext(target=target, scan_result=vuln_context.scan_result,
                                       skill_registry=exploit_registry, memory=memory)
        exploit_result = await self._run_role_agent(exploit_agent, exploit_context, EXPLOIT_ROLE)
        all_steps.extend(exploit_result.steps)
        all_skills.extend(exploit_result.skills_used)

        # Save memory
        memory.record_target_pattern(
            target,
            [t.name for t in exploit_context.scan_result.analysis.technologies],
            [p.port for p in exploit_context.scan_result.analysis.open_ports],
        )
        memory.record_findings(
            target,
            [f.title for f in exploit_context.scan_result.findings],
        )
        memory.save()

        return AgentResult(
            target=target,
            scan_result=exploit_context.scan_result,
            steps=all_steps,
            total_findings=len(exploit_context.scan_result.findings),
            skills_used=list(set(all_skills)),
        )

    async def _run_role_agent(
        self, agent: "PentestAgent", context: "AgentContext", role: AgentRole,
    ) -> AgentResult:
        """Run a single role agent's decision loop."""
        from argus_lite.core.agent import _call_llm

        steps: list[AgentStep] = []
        skills_used: list[str] = []

        for step_num in range(agent._max_steps):
            # Ask LLM for next action (with role context)
            system = (
                f"You are the {role.name} agent. {role.description}\n"
                f"{role.system_prompt_extra}\n"
                f"Available skills: {context.skill_registry.to_llm_description()}\n"
                "Respond with JSON: {{\"thought\": \"...\", \"action\": \"skill_name\", \"input\": {{}}}}\n"
                "When done: {{\"thought\": \"...\", \"action\": \"done\"}}"
            )
            decision = await _call_llm(agent._config, system, context.build_llm_context())

            action = decision.get("action", "done")
            thought = decision.get("thought", "")

            if action == "done":
                steps.append(AgentStep(
                    step_number=step_num + 1, thought=thought,
                    action="done", result_summary=f"{role.name} agent finished",
                ))
                break

            # Execute skill
            params = decision.get("input", {})
            if "target" not in params:
                params["target"] = context.target

            result = await context.skill_registry.execute(action, params, context)

            step = AgentStep(
                step_number=step_num + 1,
                thought=thought,
                action=action,
                params=params,
                result_summary=result.summary or result.error,
                result_success=result.success,
                findings_count=len(result.findings),
            )
            steps.append(step)
            skills_used.append(action)
            context.update_from_result(action, result)

        return AgentResult(
            target=context.target,
            scan_result=context.scan_result,
            steps=steps,
            skills_used=skills_used,
            total_findings=len(context.scan_result.findings),
        )
