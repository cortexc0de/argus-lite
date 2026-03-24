"""Results Tab — browse past scans, view details."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Label, RichLog, Static

_CSS = """
ResultsTab { height: 1fr; }

#results-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

#results-body { height: 1fr; }
#scans-list { width: 1fr; margin-right: 1; }

#scan-detail {
    width: 1fr;
    border: round #30363d;
    border-title-color: #58a6ff;
    background: #0d1117;
    padding: 0 1;
}

#results-actions { height: 3; margin-top: 1; }
"""


class ResultsTab(Static):
    """Browse and inspect past scan results."""

    DEFAULT_CSS = _CSS

    def compose(self) -> ComposeResult:
        yield Label("SCAN HISTORY", id="results-title")
        with Horizontal(id="results-body"):
            yield DataTable(id="scans-list")
            yield RichLog(id="scan-detail", highlight=True)
        with Horizontal(id="results-actions"):
            yield Button("Refresh", id="refresh-scans")
            yield Button("Open in Browser", id="open-report")

    def on_mount(self) -> None:
        detail = self.query_one("#scan-detail", RichLog)
        detail.border_title = "Details"
        detail.write("[dim]Select a scan to view details[/dim]")

        table = self.query_one("#scans-list", DataTable)
        table.add_columns("ID", "Target", "Date", "Findings", "Risk")
        table.cursor_type = "row"
        self._scan_data: dict[str, object] = {}
        self._load_scans()

    def _load_scans(self) -> None:
        from argus_lite.core.resume import load_partial

        table = self.query_one("#scans-list", DataTable)
        table.clear()
        self._scan_data.clear()

        scans_dir = Path.home() / ".argus-lite" / "scans"
        if not scans_dir.is_dir():
            return

        for scan_dir in sorted(scans_dir.iterdir(), reverse=True):
            if not scan_dir.is_dir():
                continue
            partial = load_partial(scan_dir)
            if not partial:
                continue
            self._scan_data[partial.scan_id] = partial
            risk = partial.risk_summary.risk_level if partial.risk_summary else "—"
            date = partial.started_at.strftime("%m/%d %H:%M") if partial.started_at else "—"
            table.add_row(
                partial.scan_id[:8], partial.target, date,
                str(len(partial.findings)), risk,
                key=partial.scan_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        scan_id = str(event.row_key.value)
        scan = self._scan_data.get(scan_id)
        if not scan:
            return
        log = self.query_one("#scan-detail", RichLog)
        log.clear()
        risk = scan.risk_summary.risk_level if scan.risk_summary else "NONE"
        rc = {"NONE": "#00ff41", "LOW": "#00aaff", "MEDIUM": "#ffaa00", "HIGH": "#ff4444"}.get(risk, "white")

        log.write(f"[bold #00ff41]Target:[/bold #00ff41] {scan.target}")
        log.write(f"[bold #00ff41]Status:[/bold #00ff41] {scan.status}")
        log.write(f"[bold #00ff41]Risk:[/bold #00ff41] [{rc}]{risk}[/{rc}]")
        log.write(f"[bold #00ff41]Tools:[/bold #00ff41] {', '.join(scan.tools_used[:6])}")

        if scan.findings:
            log.write("")
            log.write(f"[bold]Findings ({len(scan.findings)}):[/bold]")
            for f in scan.findings[:20]:
                sev_c = "#00ff41" if f.severity == "INFO" else "#ffaa00"
                log.write(f"  [{sev_c}]{f.severity}[/{sev_c}] {f.title}")
            if len(scan.findings) > 20:
                log.write(f"  [dim]... and {len(scan.findings) - 20} more[/dim]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh-scans":
            self._load_scans()
        elif event.button.id == "open-report":
            self._open_report()

    def _open_report(self) -> None:
        import webbrowser
        table = self.query_one("#scans-list", DataTable)
        if table.cursor_row is None:
            self.notify("Select a scan first", severity="warning")
            return
        row = table.get_row_at(table.cursor_row)
        short_id = str(row[0]) if row else None
        if not short_id:
            return
        for sid in self._scan_data:
            if sid.startswith(short_id):
                report = Path.home() / ".argus-lite" / "scans" / sid / "report" / "report.html"
                if report.exists():
                    webbrowser.open(f"file://{report}")
                    self.notify("Opened in browser")
                else:
                    self.notify("No HTML report", severity="warning")
                break
