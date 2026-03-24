"""Continuous monitoring models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from argus_lite.models.finding import Finding


class MonitorConfig(BaseModel):
    target: str
    interval_seconds: int = 86400
    notify_on_new: bool = True
    notify_on_resolved: bool = False
    max_runs: int | None = None
    preset: str = "quick"


class MonitorRun(BaseModel):
    run_number: int
    timestamp: datetime
    scan_id: str = ""
    findings_count: int = 0
    new_count: int = 0
    resolved_count: int = 0
    unchanged_count: int = 0
    risk_level: str = "NONE"


class MonitorState(BaseModel):
    monitor_id: str
    config: MonitorConfig
    runs: list[MonitorRun] = []
    last_findings: list[Finding] = []
    started_at: datetime
    is_running: bool = False
