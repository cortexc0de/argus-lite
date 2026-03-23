"""Textual messages for inter-component communication."""

from __future__ import annotations

from textual.message import Message

from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult


class StageUpdate(Message):
    """Fired when a scan stage changes status."""

    def __init__(self, stage: str, status: str) -> None:
        super().__init__()
        self.stage = stage
        self.status = status


class FindingUpdate(Message):
    """Fired when a new finding is discovered during a scan."""

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding


class ScanComplete(Message):
    """Fired when the scan finishes."""

    def __init__(self, result: ScanResult) -> None:
        super().__init__()
        self.result = result
