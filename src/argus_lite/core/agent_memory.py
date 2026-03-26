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

        # Cross-target: find similar targets
        similar = self.find_similar_targets(
            patterns.get("tech_stack", []),
            patterns.get("ports", []),
        )
        if similar:
            parts.append(f"Similar targets: {', '.join(s['target'] for s in similar[:3])}")

        return " | ".join(parts) if parts else ""

    # ── Smart retrieval (v4) ──

    def find_similar_targets(self, tech_stack: list[str], ports: list[int]) -> list[dict]:
        """Find past targets with similar tech/ports using Jaccard similarity."""
        if not tech_stack and not ports:
            return []

        query_set = set(t.lower() for t in tech_stack) | set(str(p) for p in ports)
        scored: list[tuple[float, str]] = []

        for target, patterns in self.target_patterns.items():
            target_set = set(t.lower() for t in patterns.get("tech_stack", []))
            target_set |= set(str(p) for p in patterns.get("ports", []))
            if not target_set:
                continue
            # Jaccard similarity
            intersection = len(query_set & target_set)
            union = len(query_set | target_set)
            similarity = intersection / union if union > 0 else 0
            if similarity > 0.2:
                scored.append((similarity, target))

        scored.sort(reverse=True)
        return [{"target": t, "similarity": round(s, 2)} for s, t in scored[:5]]

    def find_similar_payloads(self, vuln_type: str, tech: str = "") -> list[dict]:
        """Find payloads that worked on similar vuln_type + tech combos."""
        results = []
        for target, payloads in self.successful_payloads.items():
            target_tech = self.target_patterns.get(target, {}).get("tech_stack", [])
            for p in payloads:
                if p.get("vuln_type", "").lower() == vuln_type.lower():
                    # Bonus if tech matches
                    tech_match = tech.lower() in [t.lower() for t in target_tech] if tech else False
                    results.append({**p, "target": target, "tech_match": tech_match})
        # Sort: tech matches first
        results.sort(key=lambda r: r.get("tech_match", False), reverse=True)
        return results[:5]

    def get_success_rate(self, skill_name: str) -> float:
        """Rough success rate: how many targets had findings after this skill."""
        total = len(self.past_findings)
        if total == 0:
            return 0.0
        with_findings = sum(1 for findings in self.past_findings.values() if findings)
        return with_findings / total
