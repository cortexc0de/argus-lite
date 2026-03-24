"""Monitor Tab — continuous monitoring (placeholder, enabled in Phase 3)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Input, Label, Select, Static, Switch


class MonitorTab(Static):
    """Continuous monitoring setup — coming in next release."""

    DEFAULT_CSS = """
    MonitorTab { height: 100%; padding: 2 4; }
    #monitor-title { text-style: bold; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Continuous Monitoring", id="monitor-title")
            yield Label("[dim]Repeat scans automatically, get notified on new findings.[/dim]")
            yield Label("")
            yield Label("Target")
            yield Input(placeholder="example.com", id="monitor-target")
            yield Label("Interval")
            yield Select(
                [("3600", "1 hour"), ("21600", "6 hours"),
                 ("43200", "12 hours"), ("86400", "24 hours")],
                value="86400", id="monitor-interval", allow_blank=False,
            )
            yield Label("Notify on new findings")
            yield Switch(id="monitor-notify", value=True)
            yield Label("")
            yield Label("[yellow]Coming in v1.6.0 — use CLI for now: argus monitor TARGET --interval 24h[/yellow]")
            yield Label("")
            yield DataTable(id="monitor-history")

    def on_mount(self) -> None:
        table = self.query_one("#monitor-history", DataTable)
        table.add_columns("Run", "Date", "New", "Resolved", "Risk")
