from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class PipelineStage(BaseModel):
    name: str
    tools: list[str] = []
    auto: bool = False  # If True, runs automatically (e.g., report)


class PipelineDefinition(BaseModel):
    stages: list[PipelineStage]


def load_pipeline(path: str | Path) -> PipelineDefinition:
    """Load pipeline from YAML file."""
    import yaml

    raw = yaml.safe_load(Path(path).read_text())
    return PipelineDefinition.model_validate(raw)
