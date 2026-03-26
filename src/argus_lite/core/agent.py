"""AI Agent v3 — Autonomous pentesting with skill execution, planning, and memory.

Architecture:
  LLM plans → Skill executes → Result feeds back → LLM adapts → repeat

The agent loop is CLOSED: decisions are executed, results inform next decisions.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

import httpx

from argus_lite.core.agent_context import AgentContext, AgentPlan, AgentResult, AgentStep
from argus_lite.core.agent_memory import AgentMemory
from argus_lite.core.config import AIConfig, AppConfig
from argus_lite.core.skills import SkillRegistry, SkillResult
from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)

# ── System Prompts ──

_AGENT_SYSTEM = """You are an autonomous penetration testing agent. You control security tools through skills.

{available_skills}

Your workflow:
1. ANALYZE current data (tech stack, ports, URLs, existing findings)
2. DECIDE which skill to run next based on attack potential
3. After receiving results, ADAPT your strategy

Respond ONLY with valid JSON:
{{
  "thought": "Your reasoning — what did you observe? what's the best next move?",
  "action": "skill_name",
  "input": {{"key": "value"}},
  "priority": "high|medium|low"
}}

When done:
{{
  "thought": "Summary of assessment",
  "action": "done",
  "input": {{}},
  "report": "Executive summary of all findings"
}}

Strategy rules:
- High-value targets first: APIs with ID params (IDOR), redirects (SSRF), auth endpoints
- If tech stack detected (e.g., WordPress, Laravel) → use tech-specific checks
- If XSS found → check if it chains with CSRF
- If IDOR found → test privilege escalation
- If scan result is empty → try different approach
- Don't repeat skills that already ran
- test_payload: use for custom HTTP requests with specific payloads
"""

_PLANNER_SYSTEM = """You are a penetration testing strategist. Given recon data, create an attack plan.

Respond ONLY with valid JSON:
{{
  "goal": "What you're trying to achieve (e.g., 'Find data access vulnerabilities in API')",
  "steps": [
    "Step 1: description",
    "Step 2: description"
  ]
}}

Rules:
- Focus on the highest-impact attack vectors based on tech stack
- Include fallback steps (if step X fails, try Y)
- Max 8 steps
- Be specific about which endpoints/params to test
"""

_CLASSIFY_PROMPT = """Analyze these URLs from a security perspective.
For each URL, identify vulnerability potential.

URLs:
{urls}

Tech stack: {tech_stack}

Respond with JSON:
{{
  "endpoints": [
    {{
      "url": "...",
      "type": "auth|payment|search|admin|api|file|redirect",
      "vulns_to_test": ["XSS", "SQLi", "IDOR"],
      "priority": "high|medium|low",
      "reason": "why"
    }}
  ],
  "attack_strategy": "overall approach"
}}
"""

_PAYLOAD_PROMPT = """Generate targeted payloads for this scenario:

URL: {url}
Vulnerability: {vuln_type}
Tech stack: {tech_stack}
Parameter: {param}
Context: {context}

Respond with JSON:
{{
  "payloads": [
    {{"payload": "...", "technique": "...", "confidence": "high|medium|low"}}
  ]
}}
"""


class AgentPlanner:
    """LLM-powered attack planner — creates goal-based plans from recon data."""

    def __init__(self, config: AIConfig) -> None:
        self._config = config

    async def create_plan(self, context: AgentContext) -> AgentPlan:
        """Generate attack plan from current scan data."""
        prompt = context.build_llm_context()
        result = await _call_llm(self._config, _PLANNER_SYSTEM, prompt)

        return AgentPlan(
            goal=result.get("goal", "Assess target security"),
            steps=result.get("steps", ["scan_nuclei", "check_headers"]),
        )

    async def adapt_plan(self, context: AgentContext, failed_skill: str) -> AgentPlan:
        """Adjust plan when a skill fails."""
        plan = context.plan or AgentPlan()
        plan.failed.append(failed_skill)

        prompt = (
            f"The skill '{failed_skill}' failed. "
            f"Current progress: completed={plan.completed}, failed={plan.failed}. "
            f"Remaining steps: {[s for s in plan.steps if s not in plan.completed and s not in plan.failed]}. "
            f"Adapt the plan. What should we do instead?"
        )
        result = await _call_llm(self._config, _PLANNER_SYSTEM, prompt)

        return AgentPlan(
            goal=result.get("goal", plan.goal),
            steps=result.get("steps", plan.steps),
            completed=plan.completed,
            failed=plan.failed,
        )


class PentestAgent:
    """Autonomous pentesting agent with skill execution, planning, and memory.

    The agent loop: plan → decide → EXECUTE → feedback → adapt → repeat
    """

    def __init__(
        self,
        config: AIConfig,
        skill_registry: SkillRegistry | None = None,
        max_steps: int = 15,
        on_step: Callable[[AgentStep], None] | None = None,
    ) -> None:
        self._config = config
        self._skill_registry = skill_registry
        self._max_steps = max_steps
        self._on_step = on_step
        self._history: list[dict] = []
        self._memory: dict[str, Any] = {}

    async def run(self, target: str, app_config: AppConfig) -> AgentResult:
        """Full autonomous agent run with closed execution loop."""
        from argus_lite.core.skills import build_skill_registry

        registry = self._skill_registry or build_skill_registry(app_config)
        memory = AgentMemory()
        memory.load()

        context = AgentContext(
            target=target,
            skill_registry=registry,
            memory=memory,
        )

        # Phase 1: Quick recon
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.risk_scorer import score_scan

        orch = ScanOrchestrator(target=target, config=app_config, preset="quick", skip_cve=True)
        context.scan_result = await orch.run()
        context.scan_result.risk_summary = score_scan(context.scan_result)

        # Phase 2: LLM creates attack plan
        planner = AgentPlanner(self._config)
        context.plan = await planner.create_plan(context)

        # Phase 3: Execute loop — decide → execute → feedback → adapt
        skills_used: list[str] = []

        for step_num in range(self._max_steps):
            decision = await self._decide(context)
            action = decision.get("action", "done")
            thought = decision.get("thought", "")

            if action == "done":
                step = AgentStep(
                    step_number=step_num + 1, thought=thought,
                    action="done", result_summary=decision.get("report", "Assessment complete"),
                )
                context.history.append(step)
                if self._on_step:
                    self._on_step(step)
                break

            # EXECUTE THE SKILL
            params = decision.get("input", {})
            if "target" not in params:
                params["target"] = target

            skill_result = await registry.execute(action, params, context)

            # Record step
            step = AgentStep(
                step_number=step_num + 1,
                thought=thought,
                action=action,
                params=params,
                result_summary=skill_result.summary or skill_result.error,
                result_success=skill_result.success,
                findings_count=len(skill_result.findings),
            )
            context.history.append(step)
            skills_used.append(action)

            if self._on_step:
                self._on_step(step)

            # Update context with results
            context.update_from_result(action, skill_result)

            # Update plan tracking
            if context.plan:
                if skill_result.success:
                    context.plan.completed.append(action)
                else:
                    context.plan = await planner.adapt_plan(context, action)

            # Record successes to memory
            if skill_result.success and skill_result.findings:
                for f in skill_result.findings:
                    memory.record_success(target, f.evidence, f.type, f.asset)

        # Save memory
        memory.record_target_pattern(
            target,
            [t.name for t in context.scan_result.analysis.technologies],
            [p.port for p in context.scan_result.analysis.open_ports],
        )
        memory.record_findings(
            target,
            [f.title for f in context.scan_result.findings],
        )
        memory.save()

        return AgentResult(
            target=target,
            scan_result=context.scan_result,
            plan=context.plan,
            steps=context.history,
            total_findings=len(context.scan_result.findings),
            skills_used=skills_used,
        )

    # ── Backward-compatible methods (from v2) ──

    async def classify_endpoints(self, urls: list[str], tech_stack: list[str]) -> dict:
        """LLM classifies URLs by vulnerability potential."""
        prompt = _CLASSIFY_PROMPT.format(
            urls="\n".join(urls[:50]),
            tech_stack=", ".join(tech_stack) or "unknown",
        )
        return await _call_llm(self._config, "Respond ONLY with valid JSON.", prompt)

    async def generate_payloads(self, url: str, vuln_type: str,
                                tech_stack: list[str], param: str = "",
                                context: str = "") -> dict:
        """LLM generates context-specific attack payloads."""
        prompt = _PAYLOAD_PROMPT.format(
            url=url, vuln_type=vuln_type,
            tech_stack=", ".join(tech_stack) or "unknown",
            param=param, context=context,
        )
        return await _call_llm(self._config, "Respond ONLY with valid JSON.", prompt)

    async def decide_next_action(self, scan_result: ScanResult) -> dict:
        """Legacy: decide next action from ScanResult (v2 compat)."""
        context = AgentContext(target=scan_result.target, scan_result=scan_result)
        return await self._decide(context)

    async def analyze_response(self, url: str, response_data: dict) -> dict:
        """LLM analyzes HTTP response for security issues."""
        prompt = f"Analyze HTTP response:\nURL: {url}\nStatus: {response_data.get('status_code')}\nHeaders: {json.dumps(response_data.get('headers', {}))[:400]}\nBody: {response_data.get('body', '')[:200]}"
        return await _call_llm(self._config, "Respond ONLY with valid JSON.", prompt)

    def record_step(self, decision: dict, result_summary: str = "") -> None:
        """Legacy: record step (v2 compat)."""
        self._history.append({"decision": decision, "result_summary": result_summary})

    # ── Internal ──

    async def _decide(self, context: AgentContext) -> dict:
        """Ask LLM for next action based on current context."""
        skills_desc = context.skill_registry.to_llm_description() if context.skill_registry else ""
        system = _AGENT_SYSTEM.format(available_skills=skills_desc)
        user_prompt = context.build_llm_context()
        return await _call_llm(self._config, system, user_prompt)


# ── Shared LLM call helper ──

async def _call_llm(config: AIConfig, system_prompt: str, user_prompt: str) -> dict:
    """Call LLM and return parsed JSON response."""
    if not config.api_key:
        return {"error": "No AI API key configured"}

    url = f"{config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": config.max_tokens,
        "temperature": 0.4,
    }
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

        if resp.status_code != 200:
            return {"error": f"API returned {resp.status_code}"}

        data = resp.json()
        content = data["choices"][0]["message"]["content"]

        text = content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])

        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw_response": content if "content" in dir() else "", "error": "Invalid JSON"}
    except Exception as exc:
        return {"error": str(exc)}
