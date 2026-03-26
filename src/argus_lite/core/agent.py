"""AI Agent — LLM-driven autonomous pentesting orchestration.

The agent uses LLM as a decision engine:
1. Analyzer: what is this endpoint? what tech stack?
2. Strategist: where to attack? what vectors?
3. Payload Generator: context-specific payloads
4. Loop Controller: what to do next?

Architecture:
  LLM Agent → Skill Executor → Tools → Results → LLM Agent (loop)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from argus_lite.core.config import AIConfig
from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)

# System prompt that makes LLM an autonomous pentester
_AGENT_SYSTEM = """You are an autonomous penetration testing agent. You control a security scanner through skills.

Available skills:
- enumerate_subdomains: Find subdomains for a target domain
- probe_http: Check which hosts are alive via HTTP
- crawl_site: Discover all URLs and endpoints on a target
- scan_nuclei: Run vulnerability templates against targets
- fuzz_paths: Brute-force directories and files
- scan_xss: Test for XSS vulnerabilities using Dalfox
- scan_sqli: Test for SQL injection using SQLMap
- check_headers: Analyze HTTP security headers
- detect_tech: Identify technologies (CMS, framework, server)

Your job:
1. ANALYZE what you know about the target
2. DECIDE which skill to run next (or "done" if finished)
3. EXPLAIN your reasoning

Respond ONLY with valid JSON:
{
  "thought": "Your reasoning about what to do next",
  "action": "skill_name",
  "input": {"key": "value"},
  "priority_targets": ["list of interesting endpoints/findings to focus on"]
}

If you are done analyzing, respond:
{
  "thought": "Summary of findings",
  "action": "done",
  "input": {},
  "report": "Executive summary of the assessment"
}

Rules:
- Focus on high-impact vulnerabilities first (IDOR, SQLi, XSS, SSRF, RCE)
- Skip low-value checks if you find something critical
- Generate context-specific hypotheses based on the tech stack
- If you see /api/user?id=123, think IDOR
- If you see redirect?url=, think SSRF/open redirect
- If you see GraphQL, think introspection/IDOR
- Be efficient: don't repeat scans
"""

_CLASSIFY_PROMPT = """Analyze these URLs from a security perspective.
For each URL, identify:
1. What type of endpoint is it? (auth, payment, search, admin, API, file, redirect)
2. What parameters could be vulnerable?
3. What vulnerability types to test? (XSS, SQLi, SSRF, IDOR, LFI, RCE)
4. Priority: high/medium/low

URLs:
{urls}

Tech stack: {tech_stack}

Respond with JSON:
{{
  "endpoints": [
    {{
      "url": "...",
      "type": "auth|payment|search|admin|api|file|redirect",
      "params_at_risk": ["param1", "param2"],
      "vulns_to_test": ["XSS", "SQLi", "IDOR"],
      "priority": "high|medium|low",
      "reason": "why this is interesting"
    }}
  ],
  "attack_strategy": "overall approach recommendation"
}}
"""

_PAYLOAD_PROMPT = """Generate a targeted payload for this specific scenario:

Target URL: {url}
Vulnerability type: {vuln_type}
Technology stack: {tech_stack}
Parameter: {param}
Context: {context}

Generate 3 payloads ranked by likelihood of success.
Consider WAF bypass techniques if applicable.

Respond with JSON:
{{
  "payloads": [
    {{
      "payload": "the actual payload string",
      "technique": "what technique this uses",
      "bypass": "what WAF/filter it bypasses",
      "confidence": "high|medium|low"
    }}
  ]
}}
"""


class AgentSkillResult:
    """Result from executing a skill."""

    def __init__(self, skill: str, success: bool, data: dict | None = None, error: str = ""):
        self.skill = skill
        self.success = success
        self.data = data or {}
        self.error = error


class PentestAgent:
    """LLM-driven autonomous pentesting agent.

    Uses AI to make decisions about what to scan, where to look,
    and what payloads to generate — all dynamically based on context.
    """

    def __init__(self, config: AIConfig, max_steps: int = 10) -> None:
        self._config = config
        self._max_steps = max_steps
        self._history: list[dict] = []
        self._memory: dict[str, Any] = {}

    async def classify_endpoints(
        self, urls: list[str], tech_stack: list[str],
    ) -> dict:
        """Use LLM to classify endpoints by vulnerability potential.

        Returns structured analysis of which URLs to test and how.
        """
        prompt = _CLASSIFY_PROMPT.format(
            urls="\n".join(urls[:50]),
            tech_stack=", ".join(tech_stack) or "unknown",
        )
        return await self._call_llm(prompt)

    async def generate_payloads(
        self,
        url: str,
        vuln_type: str,
        tech_stack: list[str],
        param: str = "",
        context: str = "",
    ) -> dict:
        """Use LLM to generate context-specific attack payloads."""
        prompt = _PAYLOAD_PROMPT.format(
            url=url,
            vuln_type=vuln_type,
            tech_stack=", ".join(tech_stack) or "unknown",
            param=param,
            context=context,
        )
        return await self._call_llm(prompt)

    async def decide_next_action(self, scan_result: ScanResult) -> dict:
        """Given current scan results, decide what to do next."""
        # Build context from scan results
        context = self._build_context(scan_result)

        messages = [
            {"role": "system", "content": _AGENT_SYSTEM},
        ]

        # Add history of previous decisions
        for h in self._history[-5:]:
            messages.append({"role": "assistant", "content": json.dumps(h["decision"])})
            messages.append({"role": "user", "content": f"Result: {json.dumps(h.get('result_summary', 'ok'))}"})

        messages.append({"role": "user", "content": context})

        return await self._call_llm_messages(messages)

    async def analyze_response(self, url: str, response_data: dict) -> dict:
        """Analyze an HTTP response for security issues."""
        prompt = f"""Analyze this HTTP response from a security perspective:
URL: {url}
Status: {response_data.get('status_code', '?')}
Headers: {json.dumps(response_data.get('headers', {}), indent=2)[:500]}
Body preview: {response_data.get('body', '')[:300]}

What security issues do you see? Any hints of:
- Information disclosure?
- Misconfiguration?
- Potential injection points?
- Authentication/authorization issues?

Respond with JSON:
{{"issues": [{{"type": "...", "description": "...", "severity": "high|medium|low"}}], "recommendations": ["..."]}}
"""
        return await self._call_llm(prompt)

    def record_step(self, decision: dict, result_summary: str = "") -> None:
        """Record a step in the agent's history (memory)."""
        self._history.append({
            "decision": decision,
            "result_summary": result_summary,
        })

    def _build_context(self, scan: ScanResult) -> str:
        """Build context string from scan results for the LLM."""
        lines = [f"Target: {scan.target}", f"Status: {scan.status}", ""]

        if scan.analysis.technologies:
            lines.append("Technologies:")
            for t in scan.analysis.technologies:
                lines.append(f"  - {t.name} {t.version}")

        if scan.recon.http_probes:
            lines.append(f"\nLive hosts: {len(scan.recon.http_probes)}")

        if scan.recon.crawl_results:
            lines.append(f"\nCrawled URLs ({len(scan.recon.crawl_results)}):")
            for c in scan.recon.crawl_results[:20]:
                lines.append(f"  - {c.url}")

        if scan.analysis.open_ports:
            lines.append(f"\nOpen ports: {', '.join(str(p.port) for p in scan.analysis.open_ports[:10])}")

        if scan.findings:
            lines.append(f"\nCurrent findings ({len(scan.findings)}):")
            for f in scan.findings[:10]:
                lines.append(f"  [{f.severity}] {f.title}")

        if scan.analysis.nuclei_findings:
            lines.append(f"\nNuclei results ({len(scan.analysis.nuclei_findings)}):")
            for nf in scan.analysis.nuclei_findings[:10]:
                lines.append(f"  [{nf.severity}] {nf.name}")

        lines.append("\nWhat should we do next?")
        return "\n".join(lines)

    async def _call_llm(self, prompt: str) -> dict:
        """Call LLM with a single prompt, return parsed JSON."""
        messages = [
            {"role": "system", "content": "You are a security expert. Respond ONLY with valid JSON."},
            {"role": "user", "content": prompt},
        ]
        return await self._call_llm_messages(messages)

    async def _call_llm_messages(self, messages: list[dict]) -> dict:
        """Call LLM with message history, return parsed JSON."""
        if not self._config.api_key:
            return {"error": "No AI API key configured"}

        url = f"{self._config.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self._config.model,
            "messages": messages,
            "max_tokens": self._config.max_tokens,
            "temperature": 0.4,
        }
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self._config.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)

            if resp.status_code != 200:
                return {"error": f"API returned {resp.status_code}"}

            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            # Parse JSON from response
            text = content.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:-1])

            return json.loads(text)

        except json.JSONDecodeError:
            return {"raw_response": content, "error": "Invalid JSON from LLM"}
        except Exception as exc:
            return {"error": str(exc)}
