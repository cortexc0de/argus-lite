"""Progress tracking for scan stages."""

from __future__ import annotations

from typing import Callable


class ScanProgress:
    """Tracks progress of scan stages. Can drive Rich UI or plain logging."""

    def __init__(self, stages: list[str]) -> None:
        self.stages = stages
        self.current_stage: str = ""
        self.completed: set[str] = set()
        self.skipped: set[str] = set()
        self.failed: dict[str, str] = {}

    @property
    def percent_complete(self) -> float:
        if not self.stages:
            return 100.0
        done = len(self.completed) + len(self.skipped) + len(self.failed)
        return round(done / len(self.stages) * 100, 1)

    def start_stage(self, stage: str) -> None:
        self.current_stage = stage

    def complete_stage(self, stage: str) -> None:
        self.completed.add(stage)
        if self.current_stage == stage:
            self.current_stage = ""

    def skip_stage(self, stage: str) -> None:
        self.skipped.add(stage)

    def fail_stage(self, stage: str, reason: str) -> None:
        self.failed[stage] = reason
        if self.current_stage == stage:
            self.current_stage = ""

    def as_callback(self) -> Callable[[str, str], None]:
        """Return a callback function suitable for ScanOrchestrator.on_progress."""
        def callback(stage: str, status: str) -> None:
            if status == "start":
                self.start_stage(stage)
            elif status == "done":
                self.complete_stage(stage)
            elif status == "skip":
                self.skip_stage(stage)
            elif status == "fail":
                self.fail_stage(stage, "")
        return callback
