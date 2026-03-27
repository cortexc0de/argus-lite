"""Markdown Skill Loader — parse .md files into executable agent skills.

Users create .md files with YAML frontmatter + numbered steps:

```markdown
---
name: check_wordpress
description: WordPress-specific security checks
tools: [nuclei, httpx]
---

1. Probe /wp-admin for accessibility
2. Run nuclei with wordpress tags
```

These files are auto-loaded from ~/.argus-lite/skills/ (or --skills-dir).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from argus_lite.core.skills import Skill, SkillResult
from argus_lite.models.skill import SkillDefinition

if TYPE_CHECKING:
    from argus_lite.core.agent_context import AgentContext
    from argus_lite.core.skills import SkillRegistry

logger = logging.getLogger(__name__)


class SkillParseError(Exception):
    """Raised when a .md skill file cannot be parsed."""


def parse_skill_markdown(path: Path) -> SkillDefinition:
    """Parse a .md file with YAML frontmatter into a SkillDefinition."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise SkillParseError(f"Empty skill file: {path}")

    if not text.startswith("---"):
        raise SkillParseError(f"No YAML frontmatter in: {path}")

    # Split frontmatter from body
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillParseError(f"Malformed frontmatter in: {path}")

    frontmatter_str = parts[1].strip()
    body = parts[2].strip()

    try:
        frontmatter = yaml.safe_load(frontmatter_str) or {}
    except yaml.YAMLError as exc:
        raise SkillParseError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(frontmatter, dict) or "name" not in frontmatter:
        raise SkillParseError(f"Missing 'name' in frontmatter: {path}")

    if "description" not in frontmatter:
        raise SkillParseError(f"Missing 'description' in frontmatter: {path}")

    # Extract numbered steps from body
    steps = _extract_steps(body)

    return SkillDefinition(
        name=frontmatter["name"],
        description=frontmatter["description"],
        tools=frontmatter.get("tools", []),
        steps=steps,
    )


def _extract_steps(body: str) -> list[str]:
    """Extract numbered steps (1. ..., 2. ...) from markdown body."""
    steps: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        match = re.match(r"^\d+\.\s+(.+)$", line)
        if match:
            steps.append(match.group(1))
    return steps


def load_skill_directory(directory: Path) -> list[SkillDefinition]:
    """Load all .md skill files from a directory. Skips invalid files."""
    if not directory.is_dir():
        return []

    skills: list[SkillDefinition] = []
    for md_file in sorted(directory.glob("*.md")):
        try:
            skill_def = parse_skill_markdown(md_file)
            skills.append(skill_def)
        except SkillParseError as exc:
            logger.debug("Skipping invalid skill file %s: %s", md_file.name, exc)
    return skills


def register_markdown_skills(
    registry: "SkillRegistry",
    skill_dirs: list[Path],
) -> int:
    """Load .md skills from directories and register them. Returns count added."""
    count = 0
    for d in skill_dirs:
        for skill_def in load_skill_directory(d):
            if registry.get(skill_def.name) is not None:
                logger.debug("Skipping duplicate skill name: %s", skill_def.name)
                continue
            registry.register(MarkdownSkill(skill_def))
            count += 1
    return count


class MarkdownSkill(Skill):
    """A skill loaded from a .md file. Exposes steps as structured data for the agent."""

    def __init__(self, definition: SkillDefinition) -> None:
        self._definition = definition

    @property
    def name(self) -> str:
        return self._definition.name

    @property
    def description(self) -> str:
        return self._definition.description

    async def execute(self, params: dict, context: "AgentContext") -> SkillResult:
        """Return the skill steps as structured data for the LLM agent to execute."""
        return SkillResult(
            success=True,
            data={"steps": self._definition.steps, "tools": self._definition.tools},
            summary=f"Custom skill '{self.name}': {len(self._definition.steps)} steps",
        )
