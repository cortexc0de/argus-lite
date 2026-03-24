"""Monitor Tab — continuous monitoring setup."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Input, Label, Select, Static, Switch

_CSS = """
MonitorTab { height: 1fr; }

#monitor-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

#monitor-desc {
    color: #8b949e;
    margin-bottom: 2;
}

.monitor-label {
    color: #58a6ff;
    margin: 0;
}

#monitor-hint {
    color: #ffaa00;
    margin-top: 2;
    padding: 1 2;
    background: #1a1f2e;
    border: round #30363d;
}

#monitor-history {
    margin-top: 1;
    height: 1fr;
}
"""


class MonitorTab(Static):
    """Continuous monitoring — scan on interval, alert on changes."""

    DEFAULT_CSS = _CSS

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("CONTINUOUS MONITORING", id="monitor-title")
            yield Label(
                "Automatically repeat scans and get notified when new vulnerabilities appear.",
                id="monitor-desc",
            )

            yield Label("Target", classes="monitor-label")
            yield Input(placeholder="example.com", id="monitor-target")
            yield Label("Scan Interval", classes="monitor-label")
            yield Select(
                [("Every hour", "3600"), ("Every 6 hours", "21600"),
                 ("Every 12 hours", "43200"), ("Every 24 hours", "86400")],
                value="86400", id="monitor-interval", allow_blank=False,
            )
            yield Label("Notify on new findings", classes="monitor-label")
            yield Switch(id="monitor-notify", value=True)

            yield Label(
                "Use CLI to start monitoring:\n"
                "  argus monitor example.com --interval 24h --notify",
                id="monitor-hint",
            )

            yield DataTable(id="monitor-history")

    def on_mount(self) -> None:
        table = self.query_one("#monitor-history", DataTable)
        table.add_columns("Run", "Date", "New", "Resolved", "Risk")
