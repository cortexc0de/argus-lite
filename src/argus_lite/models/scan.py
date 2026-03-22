"""ScanResult — top-level aggregator model."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from argus_lite.models.analysis import AnalysisResult
from argus_lite.models.finding import Finding, Vulnerability
from argus_lite.models.recon import ReconResult


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
    findings: list[Finding] = []
    vulnerabilities: list[Vulnerability] = []

    # Metadata
    tools_used: list[str] = []
    config_snapshot: dict = {}
    audit_log: list[AuditEntry] = []

    # Partial results support
    completed_stages: list[str] = []
    skipped_stages: list[str] = []
    errors: list[StageError] = []
