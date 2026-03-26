"""Meta-Learning — self-optimization through outcome tracking.

Tracks: which skills work best on which tech stacks.
Suggests: skill priorities based on historical effectiveness.
Optimizes: reduces time on low-yield skills, amplifies high-yield ones.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path.home() / ".argus-lite" / "agent" / "meta.json"


class SkillOutcome(BaseModel):
    """Record of a skill execution outcome."""

    skill: str
    tech: str
    success: bool
    findings_count: int = 0


class MetaLearner:
    """Self-optimization: learn which skills work best on which tech stacks."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_PATH
        # skill → tech → {success: N, fail: N, findings: N}
        self._stats: dict[str, dict[str, dict[str, int]]] = {}

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            self._stats = json.loads(self._path.read_text())
        except Exception as exc:
            logger.debug("Failed to load meta stats: %s", exc)

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._stats, indent=2))
        except Exception as exc:
            logger.debug("Failed to save meta stats: %s", exc)

    def record(self, outcome: SkillOutcome) -> None:
        """Record a skill execution outcome."""
        skill = outcome.skill
        tech = outcome.tech.lower() or "unknown"

        if skill not in self._stats:
            self._stats[skill] = {}
        if tech not in self._stats[skill]:
            self._stats[skill][tech] = {"success": 0, "fail": 0, "findings": 0}

        entry = self._stats[skill][tech]
        if outcome.success:
            entry["success"] += 1
        else:
            entry["fail"] += 1
        entry["findings"] += outcome.findings_count

    def get_skill_priority(self, skill: str, tech: str = "") -> float:
        """Get effectiveness priority for a skill on a tech stack (0.0 - 1.0).

        Based on historical success rate. Default 0.5 for unknown combos.
        """
        tech_lower = tech.lower() or "unknown"
        stats = self._stats.get(skill, {}).get(tech_lower)
        if not stats:
            return 0.5  # unknown → neutral

        total = stats["success"] + stats["fail"]
        if total < 2:
            return 0.5  # not enough data

        return stats["success"] / total

    def rank_skills(self, skills: list[str], tech: str = "") -> list[tuple[str, float]]:
        """Rank skills by effectiveness for a given tech. Returns (skill, priority) pairs."""
        ranked = [(s, self.get_skill_priority(s, tech)) for s in skills]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def suggest_optimizations(self) -> list[str]:
        """Analyze all data and suggest system optimizations."""
        suggestions = []

        for skill, tech_stats in self._stats.items():
            for tech, stats in tech_stats.items():
                total = stats["success"] + stats["fail"]
                if total < 3:
                    continue
                rate = stats["success"] / total

                if rate < 0.2:
                    suggestions.append(
                        f"Deprioritize '{skill}' on '{tech}' — only {rate:.0%} success rate ({total} attempts)"
                    )
                elif rate > 0.8 and stats["findings"] > 3:
                    suggestions.append(
                        f"Prioritize '{skill}' on '{tech}' — {rate:.0%} success, {stats['findings']} findings"
                    )

        return suggestions

    def to_llm_context(self, tech_stack: list[str]) -> str:
        """Generate optimization hints for LLM."""
        if not self._stats:
            return ""

        lines = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            for skill, tech_stats in self._stats.items():
                stats = tech_stats.get(tech_lower)
                if stats and (stats["success"] + stats["fail"]) >= 2:
                    total = stats["success"] + stats["fail"]
                    rate = stats["success"] / total
                    lines.append(f"  {skill} on {tech}: {rate:.0%} success ({total} runs)")

        if not lines:
            return ""
        return "Meta-learning insights:\n" + "\n".join(lines)
