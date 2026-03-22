"""Risk scoring models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class RiskSummary(BaseModel):
    """Overall risk assessment for a scan."""

    overall_score: int = 0
    risk_level: Literal["NONE", "LOW", "MEDIUM", "HIGH"] = "NONE"
    breakdown: dict[str, int] = {}
