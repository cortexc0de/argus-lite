"""AI analysis models."""

from __future__ import annotations

from pydantic import BaseModel


class AttackChain(BaseModel):
    """A realistic attack scenario connecting multiple findings."""

    name: str
    steps: list[str]
    severity: str = "MEDIUM"
    likelihood: str = "MEDIUM"


class PrioritizedFinding(BaseModel):
    """A finding re-ranked by AI based on exploitability."""

    original_id: str
    new_priority: int
    reason: str
    exploitability: str = "MODERATE"  # EASY / MODERATE / HARD


class AIAnalysis(BaseModel):
    """Complete AI analysis of scan results."""

    executive_summary: str = ""
    attack_chains: list[AttackChain] = []
    prioritized_findings: list[PrioritizedFinding] = []
    recommendations: list[str] = []
    trend_analysis: str = ""
    model_used: str = ""
    tokens_used: int = 0
