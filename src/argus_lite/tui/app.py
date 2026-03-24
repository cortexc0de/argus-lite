"""Argus interactive TUI — full tabbed application."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from argus_lite.core.config import AppConfig, load_config
from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult
from argus_lite.tui.messages import FindingUpdate, ScanComplete, StageUpdate
from argus_lite.tui.tabs.monitor_tab import MonitorTab
from argus_lite.tui.tabs.osint_tab import OsintTab
from argus_lite.tui.tabs.results_tab import ResultsTab
from argus_lite.tui.tabs.scan_tab import ScanTab
from argus_lite.tui.tabs.settings_tab import SettingsTab

CSS = """
Screen { background: $surface; }
TabbedContent { height: 1fr; }
TabPane { padding: 1; }
"""


class ArgusApp(App):
    """Argus Lite — full interactive TUI with tabs."""

    TITLE = "Argus"
    SUB_TITLE = "Security Scanner"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
        ("f1", "tab_scan", "Scan"),
        ("f2", "tab_settings", "Settings"),
        ("f3", "tab_results", "Results"),
        ("f4", "tab_osint", "OSINT"),
        ("f5", "tab_monitor", "Monitor"),
    ]
    CSS = CSS

    def __init__(
        self,
        target: str | None = None,
        config: AppConfig | None = None,
        preset: str = "quick",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._target = target
        self._config = config
        self._preset = preset
        self._result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        from pathlib import Path

        config = self._config or load_config(
            Path.home() / ".argus-lite" / "config.yaml"
        )

        yield Header()
        with TabbedContent(initial="tab-scan"):
            with TabPane("Scan", id="tab-scan"):
                yield ScanTab(config=config)
            with TabPane("Settings", id="tab-settings"):
                yield SettingsTab(config=config)
            with TabPane("Results", id="tab-results"):
                yield ResultsTab()
            with TabPane("OSINT", id="tab-osint"):
                yield OsintTab(config=config)
            with TabPane("Monitor", id="tab-monitor"):
                yield MonitorTab()
        yield Footer()

    def on_mount(self) -> None:
        if self._target:
            # Pre-fill target if provided (e.g., from argus scan --tui)
            try:
                inp = self.query_one("#scan-target")
                inp.value = self._target
            except Exception:
                pass

    # F-key tab switching
    def action_tab_scan(self) -> None:
        self.query_one(TabbedContent).active = "tab-scan"

    def action_tab_settings(self) -> None:
        self.query_one(TabbedContent).active = "tab-settings"

    def action_tab_results(self) -> None:
        self.query_one(TabbedContent).active = "tab-results"

    def action_tab_osint(self) -> None:
        self.query_one(TabbedContent).active = "tab-osint"

    def action_tab_monitor(self) -> None:
        self.query_one(TabbedContent).active = "tab-monitor"

    # Bubble up scan events for the scan tab
    def on_scan_complete(self, msg: ScanComplete) -> None:
        self._result = msg.result
