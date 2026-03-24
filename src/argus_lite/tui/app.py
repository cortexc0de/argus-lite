"""Argus TUI — professional security scanner interface."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from argus_lite.core.config import AppConfig, load_config
from argus_lite.models.scan import ScanResult
from argus_lite.tui.messages import ScanComplete
from argus_lite.tui.tabs.monitor_tab import MonitorTab
from argus_lite.tui.tabs.osint_tab import OsintTab
from argus_lite.tui.tabs.results_tab import ResultsTab
from argus_lite.tui.tabs.scan_tab import ScanTab
from argus_lite.tui.tabs.settings_tab import SettingsTab

_CSS = """
$accent: #00ff41;
$accent-dim: #00cc33;
$surface-bright: #1a1f2e;
$panel: #0f1219;
$danger: #ff4444;
$warning: #ffaa00;
$info: #00aaff;

Screen {
    background: $panel;
}

Header {
    background: $surface-bright;
    color: $accent;
    text-style: bold;
    dock: top;
    height: 3;
}

Footer {
    background: $surface-bright;
}

TabbedContent {
    height: 1fr;
}

ContentSwitcher {
    background: $panel;
}

TabPane {
    padding: 1 2;
    background: $panel;
}

Tabs {
    background: $surface-bright;
}

Tab {
    padding: 1 3;
    color: #8b949e;
}

Tab.-active {
    color: $accent;
    text-style: bold;
}

Tab:hover {
    color: white;
}

Collapsible {
    background: $surface-bright;
    border: round #30363d;
    margin: 0 0 1 0;
    padding: 0 1;
}

CollapsibleTitle {
    color: $accent;
    text-style: bold;
    padding: 1 0;
}

Input {
    border: tall #30363d;
    background: #0d1117;
    color: white;
    margin: 0 0 1 0;
}

Input:focus {
    border: tall $accent;
}

Button {
    margin: 1 1 0 0;
}

Button.-primary {
    background: $accent;
    color: black;
    text-style: bold;
}

Button.-primary:hover {
    background: white;
    color: black;
}

Button.-success {
    background: $accent;
    color: black;
}

Select {
    border: tall #30363d;
    background: #0d1117;
    margin: 0 0 1 0;
}

SelectCurrent {
    background: #0d1117;
    color: white;
}

Switch {
    margin: 0 0 1 0;
}

DataTable {
    background: #0d1117;
    border: round #30363d;
}

DataTable > .datatable--header {
    background: $surface-bright;
    color: $accent;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #1a2332;
    color: white;
}

DataTable > .datatable--hover {
    background: #151b26;
}

RichLog {
    background: #0d1117;
    border: round #30363d;
    padding: 0 1;
}

Label {
    color: #8b949e;
    margin: 0 0 0 0;
}

VerticalScroll {
    scrollbar-color: #30363d;
    scrollbar-color-hover: #58a6ff;
    scrollbar-color-active: $accent;
}
"""


class ArgusApp(App):
    """Argus Lite — Security Scanner TUI."""

    TITLE = "ARGUS"
    SUB_TITLE = "Security Scanner v2.0"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f1", "tab_scan", "Scan"),
        ("f2", "tab_settings", "Settings"),
        ("f3", "tab_results", "Results"),
        ("f4", "tab_osint", "OSINT"),
        ("f5", "tab_monitor", "Monitor"),
    ]
    CSS = _CSS

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
            try:
                self.query_one("#scan-target").value = self._target
            except Exception:
                pass

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

    def on_scan_complete(self, msg: ScanComplete) -> None:
        self._result = msg.result
