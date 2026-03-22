"""TDD: Tests for Rich progress display — written BEFORE implementation."""

import pytest


class TestScanProgress:
    def test_create_progress_tracker(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis", "report"])
        assert progress.stages == ["recon", "analysis", "report"]

    def test_start_stage(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis"])
        progress.start_stage("recon")
        assert progress.current_stage == "recon"

    def test_complete_stage(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis"])
        progress.start_stage("recon")
        progress.complete_stage("recon")
        assert "recon" in progress.completed

    def test_skip_stage(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis"])
        progress.skip_stage("analysis")
        assert "analysis" in progress.skipped

    def test_fail_stage(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon"])
        progress.start_stage("recon")
        progress.fail_stage("recon", "dig crashed")
        assert "recon" in progress.failed

    def test_overall_progress(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis", "report"])
        assert progress.percent_complete == 0.0
        progress.complete_stage("recon")
        assert abs(progress.percent_complete - 33.3) < 1
        progress.complete_stage("analysis")
        progress.complete_stage("report")
        assert progress.percent_complete == 100.0

    def test_as_callback(self):
        from argus_lite.utils.progress import ScanProgress

        progress = ScanProgress(stages=["recon", "analysis"])
        cb = progress.as_callback()
        cb("recon", "start")
        assert progress.current_stage == "recon"
        cb("recon", "done")
        assert "recon" in progress.completed
        cb("analysis", "skip")
        assert "analysis" in progress.skipped
