"""Goal Hierarchy Engine — mission-driven attack planning.

Instead of "find vulnerabilities", the agent pursues specific goals:
  Goal: data exfiltration
    → subgoal: bypass authentication
      → subgoal: find IDOR in API
    → subgoal: find database access
      → subgoal: test SQL injection
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from argus_lite.core.agent_context import AgentContext
    from argus_lite.core.config import AIConfig

logger = logging.getLogger(__name__)

# Pre-defined high-level mission templates
MISSIONS = {
    "data_exfiltration": {
        "description": "Gain access to sensitive data (database, files, credentials)",
        "subgoals": ["bypass_auth", "find_idor", "exploit_sqli", "find_lfi"],
    },
    "admin_access": {
        "description": "Gain administrative access to the target",
        "subgoals": ["bypass_auth", "find_privilege_escalation", "exploit_session_hijack"],
    },
    "rce": {
        "description": "Achieve remote code execution on the target",
        "subgoals": ["find_upload", "exploit_ssrf", "find_command_injection", "exploit_deserialization"],
    },
    "full_assessment": {
        "description": "Comprehensive security assessment",
        "subgoals": ["map_attack_surface", "find_all_vulns", "test_auth", "test_injection", "report"],
    },
}


class Goal(BaseModel):
    """A single goal in the hierarchy."""

    id: str
    description: str
    parent_id: str = ""
    subgoals: list["Goal"] = []
    status: str = "pending"        # pending / in_progress / achieved / failed / skipped
    achievement_condition: str = ""  # what constitutes success
    assigned_skills: list[str] = []
    priority: float = 0.5


class GoalHierarchy(BaseModel):
    """Tree of goals with a mission at the root."""

    mission: str
    root: Goal
    achieved_goals: list[str] = []
    failed_goals: list[str] = []

    def get_next_goal(self) -> Goal | None:
        """Find the highest-priority leaf goal that's actionable."""
        candidates: list[Goal] = []
        self._collect_actionable(self.root, candidates)
        if not candidates:
            return None
        candidates.sort(key=lambda g: g.priority, reverse=True)
        return candidates[0]

    def _collect_actionable(self, goal: Goal, out: list[Goal]) -> None:
        if goal.status in ("achieved", "failed", "skipped"):
            return
        if not goal.subgoals:
            # Leaf goal — actionable
            if goal.status == "pending":
                out.append(goal)
        else:
            for sg in goal.subgoals:
                self._collect_actionable(sg, out)

    def mark_achieved(self, goal_id: str, summary: str = "") -> None:
        node = self._find(self.root, goal_id)
        if node:
            node.status = "achieved"
            self.achieved_goals.append(goal_id)
            # Check if parent is now fully achieved
            if node.parent_id:
                parent = self._find(self.root, node.parent_id)
                if parent and all(sg.status == "achieved" for sg in parent.subgoals):
                    parent.status = "achieved"
                    self.achieved_goals.append(parent.id)

    def mark_failed(self, goal_id: str) -> None:
        node = self._find(self.root, goal_id)
        if node:
            node.status = "failed"
            self.failed_goals.append(goal_id)

    def _find(self, node: Goal, goal_id: str) -> Goal | None:
        if node.id == goal_id:
            return node
        for sg in node.subgoals:
            found = self._find(sg, goal_id)
            if found:
                return found
        return None

    def to_llm_context(self) -> str:
        lines = [f"Mission: {self.mission}"]
        self._render(self.root, lines, 0)
        return "\n".join(lines)

    def _render(self, goal: Goal, lines: list[str], depth: int) -> None:
        icons = {"pending": "○", "in_progress": "◉", "achieved": "✓", "failed": "✗", "skipped": "—"}
        prefix = "  " * depth
        lines.append(f"{prefix}{icons.get(goal.status, '?')} {goal.description} (p={goal.priority:.1f})")
        for sg in goal.subgoals:
            self._render(sg, lines, depth + 1)


async def create_goal_hierarchy(
    config: "AIConfig", context: "AgentContext", mission: str = "full_assessment",
) -> GoalHierarchy:
    """Use LLM to create a goal hierarchy based on recon data and mission type."""
    from argus_lite.core.agent import _call_llm

    template = MISSIONS.get(mission, MISSIONS["full_assessment"])

    prompt = f"""Create an attack goal hierarchy for target: {context.target}

Mission: {template['description']}

Known data:
{context.build_llm_context()}

Create a goal tree with specific, actionable subgoals.
Respond with JSON:
{{
  "mission": "{template['description']}",
  "root": {{
    "id": "root",
    "description": "Main goal",
    "priority": 1.0,
    "subgoals": [
      {{
        "id": "sg1",
        "description": "Specific subgoal",
        "priority": 0.8,
        "assigned_skills": ["scan_sqli"],
        "achievement_condition": "SQL injection confirmed",
        "subgoals": []
      }}
    ]
  }}
}}
"""
    result = await _call_llm(config, "You are a pentesting strategist. Respond with JSON only.", prompt)

    if "error" in result:
        # Fallback: build from template
        subgoals = [
            Goal(id=f"sg-{i}", description=sg, parent_id="root", priority=0.8 - i * 0.1)
            for i, sg in enumerate(template["subgoals"])
        ]
        root = Goal(id="root", description=template["description"], priority=1.0, subgoals=subgoals)
        return GoalHierarchy(mission=mission, root=root)

    try:
        root_data = result.get("root", {})
        root = _parse_goal(root_data)
        return GoalHierarchy(mission=result.get("mission", mission), root=root)
    except Exception:
        subgoals = [
            Goal(id=f"sg-{i}", description=sg, parent_id="root", priority=0.8 - i * 0.1)
            for i, sg in enumerate(template["subgoals"])
        ]
        root = Goal(id="root", description=template["description"], priority=1.0, subgoals=subgoals)
        return GoalHierarchy(mission=mission, root=root)


def _parse_goal(data: dict, parent_id: str = "") -> Goal:
    subgoals = [_parse_goal(sg, data.get("id", "")) for sg in data.get("subgoals", [])]
    return Goal(
        id=data.get("id", "unknown"),
        description=data.get("description", ""),
        parent_id=parent_id,
        priority=data.get("priority", 0.5),
        assigned_skills=data.get("assigned_skills", []),
        achievement_condition=data.get("achievement_condition", ""),
        subgoals=subgoals,
    )
