"""Adaptive Payload Engine — iterative refinement: try → analyze → adapt → retry."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import httpx as _httpx

from argus_lite.core.config import AIConfig
from pydantic import BaseModel

if TYPE_CHECKING:
    from argus_lite.core.agent_context import AgentContext

logger = logging.getLogger(__name__)


class PayloadAttempt(BaseModel):
    """Result of a single payload test."""

    payload: str = ""
    response_code: int = 0
    reflected: bool = False
    blocked: bool = False
    error_in_response: str = ""
    body_preview: str = ""


class PayloadEngine:
    """Iterative payload generation and testing.

    Loop: LLM generates → test_payload executes → analyze response → LLM refines
    """

    def __init__(self, config: AIConfig, max_iterations: int = 3) -> None:
        self._config = config
        self._max_iterations = max_iterations

    async def adaptive_test(
        self,
        url: str,
        param: str,
        vuln_type: str,
        tech_stack: list[str] | None = None,
    ) -> list[PayloadAttempt]:
        """Run adaptive payload loop. Returns all attempts."""
        attempts: list[PayloadAttempt] = []

        for i in range(self._max_iterations):
            # Step 1: LLM generates payload based on previous attempts
            payload = await self._generate_payload(
                url, param, vuln_type, tech_stack or [], attempts,
            )
            if not payload:
                break

            # Step 2: Send the payload
            attempt = await self._send_payload(url, param, payload)
            attempts.append(attempt)

            # Step 3: Check if successful
            if attempt.reflected or attempt.error_in_response:
                logger.info("Payload hit: %s (reflected=%s, error=%s)",
                            payload[:50], attempt.reflected, attempt.error_in_response[:50])
                break

            if attempt.blocked:
                logger.info("Payload blocked by WAF, adapting...")
                # Continue loop — LLM will see the block and try bypass

        return attempts

    async def _generate_payload(
        self,
        url: str,
        param: str,
        vuln_type: str,
        tech_stack: list[str],
        previous: list[PayloadAttempt],
    ) -> str:
        """Ask LLM to generate a payload, considering previous attempts."""
        if not self._config.api_key:
            return ""

        history = ""
        if previous:
            history = "\nPrevious attempts:\n"
            for i, a in enumerate(previous):
                status = "BLOCKED" if a.blocked else "reflected" if a.reflected else "no effect"
                history += f"  {i+1}. '{a.payload[:60]}' → HTTP {a.response_code}, {status}\n"

        prompt = f"""Generate ONE payload for:
URL: {url}
Parameter: {param}
Vulnerability: {vuln_type}
Tech stack: {', '.join(tech_stack) or 'unknown'}
{history}

{"The previous payload was BLOCKED. Try WAF bypass techniques (encoding, case change, alternate syntax)." if previous and previous[-1].blocked else ""}

Respond with ONLY the raw payload string, nothing else."""

        from argus_lite.core.agent import _call_llm
        result = await _call_llm(
            self._config,
            "You are a payload generation specialist. Return ONLY the payload string.",
            prompt,
        )

        if isinstance(result, dict):
            return result.get("payload", result.get("raw_response", ""))
        return str(result) if result else ""

    async def _send_payload(self, url: str, param: str, payload: str) -> PayloadAttempt:
        """Send payload via HTTP and analyze response."""
        test_url = url
        if "?" in url:
            test_url = f"{url}&{param}={payload}"
        else:
            test_url = f"{url}?{param}={payload}"

        try:
            async with _httpx.AsyncClient(follow_redirects=False, timeout=10, verify=False) as client:
                resp = await client.get(test_url)

            body = resp.text[:1000]
            reflected = payload in body
            blocked = resp.status_code in (403, 406, 429) or "blocked" in body.lower() or "waf" in body.lower()

            # Detect error signatures
            error = ""
            error_patterns = [
                "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
                "uncaught exception", "stack trace", "fatal error",
            ]
            for pattern in error_patterns:
                if pattern in body.lower():
                    error = pattern
                    break

            return PayloadAttempt(
                payload=payload,
                response_code=resp.status_code,
                reflected=reflected,
                blocked=blocked,
                error_in_response=error,
                body_preview=body[:200],
            )

        except Exception as exc:
            return PayloadAttempt(payload=payload, response_code=0, error_in_response=str(exc))
