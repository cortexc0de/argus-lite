"""Continuous monitoring — repeat scans, diff findings, notify on changes."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from argus_lite.core.config import AppConfig
from argus_lite.core.incremental import diff_findings
from argus_lite.models.finding import Finding
from argus_lite.models.monitor import MonitorConfig, MonitorRun, MonitorState

logger = logging.getLogger(__name__)


class MonitorSession:
    """Runs repeated scans, diffs findings, notifies on changes."""

    def __init__(
        self,
        monitor_config: MonitorConfig,
        app_config: AppConfig,
        on_run_complete: Callable[[MonitorRun], None] | None = None,
    ) -> None:
        self._mc = monitor_config
        self._app_config = app_config
        self._on_run_complete = on_run_complete
        self._shutdown = asyncio.Event()
        self._run_count = 0
        self._state = MonitorState(
            monitor_id=str(uuid.uuid4())[:8],
            config=monitor_config,
            started_at=datetime.now(tz=timezone.utc),
        )

    async def start(self) -> None:
        """Main monitoring loop. Blocks until stop() or max_runs reached."""
        self._state.is_running = True

        while not self._shutdown.is_set():
            await self._execute_run()
            self._run_count += 1

            if self._mc.max_runs and self._run_count >= self._mc.max_runs:
                break

            # Wait for interval or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown.wait(),
                    timeout=self._mc.interval_seconds,
                )
                break  # shutdown requested
            except asyncio.TimeoutError:
                continue  # interval elapsed

        self._state.is_running = False

    async def stop(self) -> None:
        """Signal graceful shutdown."""
        self._shutdown.set()

    async def _execute_run(self) -> None:
        """Single scan cycle: scan → diff → notify → record."""
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.risk_scorer import score_scan

        logger.info("Monitor run %d for %s", self._run_count + 1, self._mc.target)

        orch = ScanOrchestrator(
            target=self._mc.target,
            config=self._app_config,
            preset=self._mc.preset,
            skip_cve=True,  # Skip CVE in monitor for speed
        )

        try:
            result = await orch.run()
            result.risk_summary = score_scan(result)
        except Exception as exc:
            logger.warning("Monitor scan failed: %s", exc)
            run = MonitorRun(
                run_number=self._run_count + 1,
                timestamp=datetime.now(tz=timezone.utc),
                risk_level="NONE",
            )
            self._state.runs.append(run)
            return

        # Diff with previous findings
        current_findings = result.findings
        prev_findings = self._state.last_findings

        diff = diff_findings(prev_findings, current_findings)

        run = MonitorRun(
            run_number=self._run_count + 1,
            timestamp=datetime.now(tz=timezone.utc),
            scan_id=result.scan_id,
            findings_count=len(current_findings),
            new_count=len(diff.new),
            resolved_count=len(diff.resolved),
            unchanged_count=len(diff.unchanged),
            risk_level=result.risk_summary.risk_level if result.risk_summary else "NONE",
        )

        self._state.runs.append(run)
        self._state.last_findings = current_findings

        # Notify if new findings appeared
        if diff.new and self._mc.notify_on_new:
            await self._send_notification(result, diff.new)

        # Callback
        if self._on_run_complete:
            try:
                self._on_run_complete(run)
            except Exception:
                pass

        # Save state
        self._save_state()

    async def _send_notification(self, result, new_findings: list[Finding]) -> None:
        """Send notification about new findings."""
        try:
            from argus_lite.core.notifier import NotificationDispatcher

            if not self._app_config.notifications.enabled:
                return

            dispatcher = NotificationDispatcher(self._app_config.notifications)
            if dispatcher.get_active_notifiers():
                await dispatcher.notify_all(result)
        except Exception as exc:
            logger.warning("Monitor notification failed: %s", exc)

    def _save_state(self) -> None:
        """Persist monitor state to disk."""
        try:
            state_dir = (
                Path.home() / ".argus-lite" / "monitors" / self._state.monitor_id
            )
            state_dir.mkdir(parents=True, exist_ok=True)
            (state_dir / "state.json").write_text(
                self._state.model_dump_json(indent=2)
            )
        except Exception as exc:
            logger.debug("Failed to save monitor state: %s", exc)
