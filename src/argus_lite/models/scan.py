"""ScanResult — top-level aggregator model."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from argus_lite.models.ai import AIAnalysis
from argus_lite.models.analysis import AnalysisResult
from argus_lite.models.finding import Finding, Vulnerability
from argus_lite.models.recon import ReconResult
from argus_lite.models.risk import RiskSummary


class AuditEntry(BaseModel):
    timestamp: datetime
    action: str
    details: str = ""


class StageError(BaseModel):
    stage: str
    error_type: str
    message: str
    timestamp: datetime


class ScanResult(BaseModel):
    """Top-level scan result aggregator."""

    scan_id: str
    target: str
    target_type: str  # domain, ip, url
    status: Literal["running", "completed", "failed", "interrupted"]
    started_at: datetime
    completed_at: datetime | None = None

    # Per-module results
    recon: ReconResult = ReconResult()
    analysis: AnalysisResult = AnalysisResult()

    # Aggregated findings
    findings: list[Finding] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    # Metadata
    tools_used: list[str] = Field(default_factory=list)
    config_snapshot: dict = Field(default_factory=dict)
    audit_log: list[AuditEntry] = Field(default_factory=list)

    # Risk assessment
    risk_summary: RiskSummary | None = None

    # AI analysis
    ai_analysis: AIAnalysis | None = None

    # Partial results support
    completed_stages: list[str] = Field(default_factory=list)
    skipped_stages: list[str] = Field(default_factory=list)
    errors: list[StageError] = Field(default_factory=list)
