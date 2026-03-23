"""Bulk scan models — aggregated results across multiple targets."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from argus_lite.models.scan import ScanResult


class BulkScanSummary(BaseModel):
    """Aggregated statistics across all targets in a bulk scan."""

    total_targets: int
    completed: int
    failed: int
    live_hosts: int
    total_findings: int
    total_vulnerabilities: int
    highest_risk: str = "NONE"
    technologies_seen: list[str] = []
    top_cves: list[str] = []
    findings_by_severity: dict[str, int] = {}


class BulkScanResult(BaseModel):
    """Top-level result for a bulk (multi-target) scan session."""

    bulk_id: str
    sources: list[str]
    scan_results: list = []          # list[ScanResult] — avoid circular import
    failed_targets: list[str] = []
    summary: BulkScanSummary
    started_at: datetime
    completed_at: datetime | None = None
    preset: str = "bulk"
