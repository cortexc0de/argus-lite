"""Skill definition model — used by markdown skill loader."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SkillDefinition(BaseModel):
    """Parsed representation of a .md skill file."""

    name: str
    description: str
    tools: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
