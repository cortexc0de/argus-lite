"""AI-powered scan analysis via OpenAI-compatible API."""

from __future__ import annotations

import json
import logging

import httpx

from argus_lite.core.config import AIConfig
from argus_lite.models.ai import AIAnalysis
from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior penetration tester analyzing security scan results.
Your task is to provide actionable intelligence from the scan data.

Respond ONLY with valid JSON matching this schema:
{
  "executive_summary": "3-5 sentence overview of security posture",
  "attack_chains": [{"name": "Chain name", "steps": ["Step 1", "Step 2"], "severity": "HIGH/MEDIUM/LOW", "likelihood": "HIGH/MEDIUM/LOW"}],
  "prioritized_findings": [{"original_id": "finding-id", "new_priority": 1, "reason": "Why this matters", "exploitability": "EASY/MODERATE/HARD"}],
  "recommendations": ["Specific actionable fix 1", "Fix 2"],
  "trend_analysis": "Changes since last scan (if provided)"
}

Rules:
- Be specific to the target's technology stack
- Focus on practical exploitability, not theoretical risk
- This is a passive scanner (info/low severity only) — findings may indicate deeper issues
- Recommendations must be actionable (not "update everything")
- Do not invent findings that don't exist in the data"""


class AIAnalyzer:
    """Analyzes scan results using an OpenAI-compatible LLM."""

    def __init__(self, config: AIConfig) -> None:
        self._config = config

    async def analyze(
        self, scan: ScanResult, previous_scan: ScanResult | None = None,
    ) -> AIAnalysis:
        """Analyze scan results. Returns empty AIAnalysis on any error."""
        if not self._config.api_key:
            return AIAnalysis()

        try:
            return await self._call_llm(scan, previous_scan)
        except Exception as e:
            logger.warning("AI analysis failed: %s", e)
            return AIAnalysis()

    async def _call_llm(
        self, scan: ScanResult, previous_scan: ScanResult | None,
    ) -> AIAnalysis:
        user_prompt = self._build_user_prompt(scan, previous_scan)

        url = f"{self._config.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self._config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self._config.max_tokens,
            "temperature": 0.3,
        }
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._config.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

        if resp.status_code != 200:
            logger.warning("AI API returned status %d", resp.status_code)
            return AIAnalysis(model_used=self._config.model)

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens", 0)

        return self._parse_response(content, tokens)

    def _parse_response(self, content: str, tokens: int) -> AIAnalysis:
        # Try to extract JSON from response (may have markdown fences)
        text = content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("AI returned invalid JSON")
            return AIAnalysis(model_used=self._config.model, tokens_used=tokens)

        try:
            analysis = AIAnalysis.model_validate(parsed)
        except Exception:
            # Partial parse — take what we can
            analysis = AIAnalysis(
                executive_summary=parsed.get("executive_summary", ""),
                recommendations=parsed.get("recommendations", []),
            )

        analysis.model_used = self._config.model
        analysis.tokens_used = tokens
        return analysis

    def _build_user_prompt(
        self, scan: ScanResult, previous_scan: ScanResult | None = None,
    ) -> str:
        lines = [f"Target: {scan.target}", f"Status: {scan.status}", ""]

        # Subdomains
        if scan.recon.subdomains:
            lines.append(f"Subdomains found ({len(scan.recon.subdomains)}):")
            for s in scan.recon.subdomains[:20]:
                lines.append(f"  - {s.name}")
            lines.append("")

        # Technologies
        if scan.analysis.technologies:
            lines.append("Technologies:")
            for t in scan.analysis.technologies:
                ver = f" v{t.version}" if t.version else ""
                lines.append(f"  - {t.name}{ver}")
            lines.append("")

        # Open ports
        if scan.analysis.open_ports:
            lines.append("Open ports:")
            for p in scan.analysis.open_ports:
                lines.append(f"  - {p.port}/{p.protocol} ({p.service})")
            lines.append("")

        # Security headers
        sh = scan.analysis.security_headers
        if sh and sh.missing_headers:
            lines.append(f"Missing security headers: {', '.join(sh.missing_headers)}")
            lines.append("")

        # SSL
        ssl = scan.analysis.ssl_info
        if ssl:
            issues = []
            if ssl.expired: issues.append("EXPIRED")
            if ssl.weak_cipher: issues.append("WEAK CIPHER")
            if issues:
                lines.append(f"SSL issues: {', '.join(issues)}")
            else:
                lines.append(f"SSL: {ssl.protocol} / {ssl.cipher}")
            lines.append("")

        # Findings
        if scan.findings:
            lines.append(f"Findings ({len(scan.findings)}):")
            for f in scan.findings:
                lines.append(f"  [{f.severity}] {f.title} — {f.description}")
            lines.append("")

        # Nuclei findings
        if scan.analysis.nuclei_findings:
            lines.append(f"Nuclei findings ({len(scan.analysis.nuclei_findings)}):")
            for nf in scan.analysis.nuclei_findings:
                lines.append(f"  [{nf.severity}] {nf.name} at {nf.matched_at}")
            lines.append("")

        # Fuzz results
        if scan.analysis.fuzz_results:
            lines.append(f"Discovered paths ({len(scan.analysis.fuzz_results)}):")
            for fr in scan.analysis.fuzz_results[:10]:
                lines.append(f"  - {fr.url} ({fr.status_code})")
            lines.append("")

        # Previous scan comparison
        if previous_scan:
            lines.append("--- PREVIOUS SCAN COMPARISON ---")
            lines.append(f"Previous scan had {len(previous_scan.findings)} findings.")
            lines.append("Please provide trend analysis comparing current vs previous results.")
            lines.append("")

        return "\n".join(lines)
