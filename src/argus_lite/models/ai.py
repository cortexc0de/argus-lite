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


class RemediationCommand(BaseModel):
    """A specific command or config snippet to fix a finding."""

    finding_title: str = ""
    description: str = ""
    command: str = ""          # e.g. "add_header X-Frame-Options DENY;"
    platform: str = ""         # nginx, apache, iptables, etc.


class AIAnalysis(BaseModel):
    """Complete AI analysis of scan results."""

    executive_summary: str = ""
    attack_chains: list[AttackChain] = []
    prioritized_findings: list[PrioritizedFinding] = []
    recommendations: list[str] = []
    remediation_commands: list[RemediationCommand] = []
    trend_analysis: str = ""
    model_used: str = ""
    tokens_used: int = 0
