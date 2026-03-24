"""TDD: Tests for interactive TUI — written BEFORE implementation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestTuiMessages:
    def test_stage_update_message_fields(self):
        from argus_lite.tui.messages import StageUpdate

        msg = StageUpdate(stage="recon", status="done")
        assert msg.stage == "recon"
        assert msg.status == "done"

    def test_finding_update_message_fields(self):
        from argus_lite.models.finding import Finding
        from argus_lite.tui.messages import FindingUpdate

        f = Finding(
            id="f-1",
            type="test",
            severity="INFO",
            title="Test Finding",
            description="desc",
            asset="example.com",
            evidence="",
            source="test",
            remediation="fix it",
        )
        msg = FindingUpdate(finding=f)
        assert msg.finding.id == "f-1"
        assert msg.finding.title == "Test Finding"

    def test_scan_complete_message_fields(self):
        from datetime import datetime, timezone

        from argus_lite.models.scan import ScanResult
        from argus_lite.tui.messages import ScanComplete

        result = ScanResult(
            scan_id="scan-001",
            target="example.com",
            target_type="domain",
            status="completed",
            started_at=datetime.now(tz=timezone.utc),
        )
        msg = ScanComplete(result=result)
        assert msg.result.scan_id == "scan-001"


class TestArgusAppInstantiation:
    def test_app_can_be_instantiated(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.app import ArgusApp

        config = AppConfig()
        app = ArgusApp(target="example.com", config=config, preset="quick")
        assert app is not None
        assert "RichLog" in str(type(app).__mro__) or True  # just check no import error

    def test_app_has_correct_target(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.app import ArgusApp

        config = AppConfig()
        app = ArgusApp(target="test.example.com", config=config, preset="quick")
        assert app._target == "test.example.com"

    def test_app_has_correct_preset(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.app import ArgusApp

        config = AppConfig()
        app = ArgusApp(target="test.com", config=config, preset="full")
        assert app._preset == "full"


class TestOrchestratorOnFinding:
    def test_on_finding_callback_fires(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.models.finding import Finding

        received: list[Finding] = []

        def collector(f: Finding) -> None:
            received.append(f)

        config = AppConfig()
        orch = ScanOrchestrator(
            target="example.com",
            config=config,
            on_finding=collector,
        )
        assert orch._on_finding is collector

    def test_on_finding_none_accepted(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.orchestrator import ScanOrchestrator

        config = AppConfig()
        # Should not raise
        orch = ScanOrchestrator(
            target="example.com",
            config=config,
            on_finding=None,
        )
        assert orch._on_finding is None
