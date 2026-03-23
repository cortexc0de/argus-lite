"""YAML Scan Template — declarative scan configuration (scan DSL)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class ScanTemplateReport(BaseModel):
    format: Literal["json", "md", "html", "sarif"] = "md"
    output: str = "."


class ScanTemplateNotify(BaseModel):
    telegram: bool = False
    discord: bool = False
    slack: bool = False


class ScanTemplateAI(BaseModel):
    enabled: bool = False
    model: str = ""


class ScanTemplate(BaseModel):
    """Top-level scan template configuration."""

    version: str = "1"
    target: str
    preset: Literal["quick", "full", "recon", "web"] = "quick"
    steps: list[str] = []
    report: ScanTemplateReport = ScanTemplateReport()
    notify: ScanTemplateNotify = ScanTemplateNotify()
    ai: ScanTemplateAI = ScanTemplateAI()
    rate_limit: int = 10
    timeout: int = 30
    no_confirm: bool = False


def load_scan_template(path: str | Path) -> ScanTemplate:
    """Load a scan template from a YAML file.

    Supports ${VAR} substitution from environment variables.
    Raises FileNotFoundError if the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Template file not found: {p}")

    raw = p.read_text()

    # Substitute ${VAR} → os.environ.get(VAR, "${VAR}")
    def _sub(m: re.Match) -> str:
        return os.environ.get(m.group(1), m.group(0))

    raw = re.sub(r"\$\{(\w+)\}", _sub, raw)

    data = yaml.safe_load(raw)
    return ScanTemplate.model_validate(data)
