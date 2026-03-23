"""TDD: Tests for scan resume functionality."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus_lite.models.scan import ScanResult


def _make_partial(scan_dir: Path) -> ScanResult:
    """Create a partial scan result and save it."""
    scan = ScanResult(
        scan_id="resume-test-uuid",
        target="example.com",
        target_type="domain",
        status="interrupted",
        started_at=datetime(2026, 3, 21, 10, 0, 0, tzinfo=timezone.utc),
        completed_stages=["recon"],
        skipped_stages=["analysis"],
    )
    return scan


class TestSavePartial:
    def test_save_creates_file(self, tmp_path):
        from argus_lite.core.resume import save_partial

        scan = _make_partial(tmp_path)
        save_partial(scan, tmp_path)

        partial_file = tmp_path / "partial.json"
        assert partial_file.exists()

    def test_save_is_valid_json(self, tmp_path):
        from argus_lite.core.resume import save_partial

        scan = _make_partial(tmp_path)
        save_partial(scan, tmp_path)

        data = json.loads((tmp_path / "partial.json").read_text())
        assert data["scan_id"] == "resume-test-uuid"
        assert data["status"] == "interrupted"

    def test_save_overwrites(self, tmp_path):
        from argus_lite.core.resume import save_partial

        scan1 = _make_partial(tmp_path)
        save_partial(scan1, tmp_path)

        scan1.completed_stages.append("analysis")
        save_partial(scan1, tmp_path)

        data = json.loads((tmp_path / "partial.json").read_text())
        assert "analysis" in data["completed_stages"]


class TestLoadPartial:
    def test_load_returns_scan_result(self, tmp_path):
        from argus_lite.core.resume import load_partial, save_partial

        scan = _make_partial(tmp_path)
        save_partial(scan, tmp_path)

        loaded = load_partial(tmp_path)
        assert loaded is not None
        assert loaded.scan_id == "resume-test-uuid"
        assert loaded.target == "example.com"
        assert "recon" in loaded.completed_stages

    def test_load_missing_returns_none(self, tmp_path):
        from argus_lite.core.resume import load_partial

        loaded = load_partial(tmp_path)
        assert loaded is None

    def test_load_corrupt_returns_none(self, tmp_path):
        from argus_lite.core.resume import load_partial

        (tmp_path / "partial.json").write_text("{corrupt")
        loaded = load_partial(tmp_path)
        assert loaded is None


class TestResumeLogic:
    def test_get_remaining_stages(self):
        from argus_lite.core.resume import get_remaining_stages

        completed = ["recon"]
        all_stages = ["recon", "analysis"]
        remaining = get_remaining_stages(completed, all_stages)
        assert remaining == ["analysis"]

    def test_all_completed_returns_empty(self):
        from argus_lite.core.resume import get_remaining_stages

        remaining = get_remaining_stages(["recon", "analysis"], ["recon", "analysis"])
        assert remaining == []

    def test_none_completed_returns_all(self):
        from argus_lite.core.resume import get_remaining_stages

        remaining = get_remaining_stages([], ["recon", "analysis"])
        assert remaining == ["recon", "analysis"]
