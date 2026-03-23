"""Scan resume — save/load partial results."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)


def save_partial(scan: ScanResult, scan_dir: Path) -> None:
    """Save partial scan result to disk for later resume."""
    scan_dir.mkdir(parents=True, exist_ok=True)
    partial_file = scan_dir / "partial.json"
    partial_file.write_text(scan.model_dump_json(indent=2))


def load_partial(scan_dir: Path) -> ScanResult | None:
    """Load partial scan result from disk. Returns None if not found or corrupt."""
    partial_file = scan_dir / "partial.json"
    if not partial_file.exists():
        return None
    try:
        return ScanResult.model_validate_json(partial_file.read_text())
    except Exception as e:
        logger.warning("Failed to load partial scan: %s", e)
        return None


def get_remaining_stages(
    completed: list[str], all_stages: list[str]
) -> list[str]:
    """Return stages that haven't been completed yet."""
    completed_set = set(completed)
    return [s for s in all_stages if s not in completed_set]
