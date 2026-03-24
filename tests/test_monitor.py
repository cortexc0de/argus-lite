"""TDD: Tests for continuous monitoring — written BEFORE implementation."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.models.finding import Finding
from argus_lite.models.monitor import MonitorConfig, MonitorRun, MonitorState


def _make_finding(title: str, severity: str = "INFO") -> Finding:
    return Finding(id=f"f-{title}", type="test", severity=severity,
                   title=title, description="", asset="example.com",
                   evidence="", source="test", remediation="fix")


def _make_scan_result(target: str = "example.com", findings: list | None = None):
    from argus_lite.models.risk import RiskSummary
    from argus_lite.models.scan import ScanResult

    r = ScanResult(
        scan_id="scan-test",
        target=target,
        target_type="domain",
        status="completed",
        started_at=datetime.now(tz=timezone.utc),
        findings=findings or [],
    )
    r.risk_summary = RiskSummary(overall_score=0, risk_level="NONE")
    return r


class TestMonitorModels:
    def test_monitor_config_defaults(self):
        mc = MonitorConfig(target="example.com")
        assert mc.interval_seconds == 86400
        assert mc.preset == "quick"
        assert mc.notify_on_new is True

    def test_monitor_run(self):
        mr = MonitorRun(run_number=1, timestamp=datetime.now(tz=timezone.utc),
                        scan_id="s1", new_count=3, resolved_count=1)
        assert mr.run_number == 1
        assert mr.new_count == 3

    def test_monitor_state(self):
        ms = MonitorState(
            monitor_id="m1",
            config=MonitorConfig(target="example.com"),
            started_at=datetime.now(tz=timezone.utc),
        )
        assert ms.monitor_id == "m1"
        assert ms.is_running is False


class TestMonitorSession:
    def test_creates_with_config(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=1)
        session = MonitorSession(mc, AppConfig())
        assert session is not None

    def test_single_run_completes(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=1, interval_seconds=1)
        session = MonitorSession(mc, AppConfig())

        result = _make_scan_result(findings=[_make_finding("F1")])

        async def mock_run(self_orch):
            return result

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
            asyncio.get_event_loop().run_until_complete(session.start())

        assert len(session._state.runs) == 1
        assert session._state.runs[0].findings_count == 1
        assert session._state.is_running is False

    def test_detects_new_findings(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=2, interval_seconds=0)
        session = MonitorSession(mc, AppConfig())

        call_count = [0]

        async def mock_run(self_orch):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_scan_result(findings=[_make_finding("A")])
            else:
                return _make_scan_result(findings=[_make_finding("A"), _make_finding("B")])

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
            asyncio.get_event_loop().run_until_complete(session.start())

        assert len(session._state.runs) == 2
        assert session._state.runs[1].new_count == 1  # "B" is new

    def test_detects_resolved_findings(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=2, interval_seconds=0)
        session = MonitorSession(mc, AppConfig())

        call_count = [0]

        async def mock_run(self_orch):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_scan_result(findings=[_make_finding("A"), _make_finding("B")])
            else:
                return _make_scan_result(findings=[_make_finding("A")])

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
            asyncio.get_event_loop().run_until_complete(session.start())

        assert session._state.runs[1].resolved_count == 1  # "B" resolved

    def test_on_run_complete_callback(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        runs_received = []

        mc = MonitorConfig(target="example.com", max_runs=1, interval_seconds=0)
        session = MonitorSession(mc, AppConfig(), on_run_complete=lambda r: runs_received.append(r))

        async def mock_run(self_orch):
            return _make_scan_result()

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
            asyncio.get_event_loop().run_until_complete(session.start())

        assert len(runs_received) == 1

    def test_stop_stops_loop(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=None, interval_seconds=3600)
        session = MonitorSession(mc, AppConfig())

        async def mock_run(self_orch):
            return _make_scan_result()

        async def run_and_stop():
            with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run):
                task = asyncio.create_task(session.start())
                await asyncio.sleep(0.1)
                await session.stop()
                await task

        asyncio.get_event_loop().run_until_complete(run_and_stop())
        assert session._state.is_running is False

    def test_notifies_on_new_findings(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.monitor import MonitorSession

        mc = MonitorConfig(target="example.com", max_runs=2, interval_seconds=0,
                           notify_on_new=True)
        config = AppConfig()
        config.notifications.enabled = True
        config.notifications.telegram_token = "test"
        config.notifications.telegram_chat_id = "123"

        session = MonitorSession(mc, config)

        call_count = [0]

        async def mock_run(self_orch):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_scan_result(findings=[])
            return _make_scan_result(findings=[_make_finding("NEW")])

        with patch("argus_lite.core.orchestrator.ScanOrchestrator.run", mock_run), \
             patch("argus_lite.core.notifier.NotificationDispatcher.notify_all",
                   new_callable=AsyncMock) as mock_notify:
            asyncio.get_event_loop().run_until_complete(session.start())

        # Should have been called once (when new finding appeared)
        assert mock_notify.call_count >= 1


class TestMonitorStatePersistence:
    def test_save_and_load_state(self, tmp_path):
        from argus_lite.core.monitor import MonitorSession

        state = MonitorState(
            monitor_id="m-test",
            config=MonitorConfig(target="example.com"),
            started_at=datetime.now(tz=timezone.utc),
            runs=[MonitorRun(run_number=1, timestamp=datetime.now(tz=timezone.utc),
                             scan_id="s1", new_count=2)],
        )
        state_file = tmp_path / "state.json"
        state_file.write_text(state.model_dump_json(indent=2))

        loaded = MonitorState.model_validate_json(state_file.read_text())
        assert loaded.monitor_id == "m-test"
        assert len(loaded.runs) == 1
        assert loaded.runs[0].new_count == 2
