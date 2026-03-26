"""Agent Memory — persistent state across agent sessions."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path.home() / ".argus-lite" / "agent" / "memory.json"


class AgentMemory:
    """JSON-file persistent memory for the pentesting agent.

    Stores per-target:
    - successful payloads
    - target patterns (tech stack, ports)
    - past findings summaries
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_PATH
        self.successful_payloads: dict[str, list[dict]] = {}
        self.target_patterns: dict[str, dict] = {}
        self.past_findings: dict[str, list[str]] = {}

    def load(self) -> None:
        """Load memory from disk."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            self.successful_payloads = data.get("successful_payloads", {})
            self.target_patterns = data.get("target_patterns", {})
            self.past_findings = data.get("past_findings", {})
        except Exception as exc:
            logger.debug("Failed to load agent memory: %s", exc)

    def save(self) -> None:
        """Save memory to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "successful_payloads": self.successful_payloads,
                "target_patterns": self.target_patterns,
                "past_findings": self.past_findings,
            }
            self._path.write_text(json.dumps(data, indent=2, default=str))
        except Exception as exc:
            logger.debug("Failed to save agent memory: %s", exc)

    def record_success(self, target: str, payload: str, vuln_type: str, url: str = "") -> None:
        """Record a successful payload for a target."""
        if target not in self.successful_payloads:
            self.successful_payloads[target] = []
        self.successful_payloads[target].append({
            "payload": payload,
            "vuln_type": vuln_type,
            "url": url,
        })

    def record_target_pattern(self, target: str, tech_stack: list[str], ports: list[int]) -> None:
        """Record target characteristics for future reference."""
        self.target_patterns[target] = {
            "tech_stack": tech_stack,
            "ports": ports,
        }

    def record_findings(self, target: str, finding_titles: list[str]) -> None:
        """Record finding titles for a target."""
        self.past_findings[target] = finding_titles

    def get_context_for_target(self, target: str) -> str:
        """Get memory context string for LLM prompt."""
        parts = []

        payloads = self.successful_payloads.get(target, [])
        if payloads:
            parts.append(f"Past successful payloads: {len(payloads)}")
            for p in payloads[-3:]:
                parts.append(f"  {p['vuln_type']}: {p['payload'][:60]}")

        patterns = self.target_patterns.get(target, {})
        if patterns:
            parts.append(f"Known tech: {', '.join(patterns.get('tech_stack', []))}")

        past = self.past_findings.get(target, [])
        if past:
            parts.append(f"Past findings: {', '.join(past[-5:])}")

        return " | ".join(parts) if parts else ""
