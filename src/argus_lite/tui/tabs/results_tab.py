"""Results Tab — browse past scans, view details, compare."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, RichLog, Static


class ResultsTab(Static):
    """Browse and compare past scan results."""

    DEFAULT_CSS = """
    ResultsTab { height: 100%; }
    #results-body { height: 1fr; }
    #scans-list { width: 1fr; }
    #scan-detail { width: 1fr; border: round #58a6ff; padding: 0 1; }
    #results-actions { height: 3; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="results-body"):
            yield DataTable(id="scans-list")
            yield RichLog(id="scan-detail", highlight=True)
        with Horizontal(id="results-actions"):
            yield Button("Refresh", id="refresh-scans")
            yield Button("Open Report", id="open-report")

    def on_mount(self) -> None:
        table = self.query_one("#scans-list", DataTable)
        table.add_columns("ID", "Target", "Status", "Date", "Findings", "Risk")
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
            date = partial.started_at.strftime("%m-%d %H:%M") if partial.started_at else "—"
            table.add_row(
                partial.scan_id[:8], partial.target, partial.status,
                date, str(len(partial.findings)), risk,
                key=partial.scan_id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        scan_id = str(event.row_key.value)
        scan = self._scan_data.get(scan_id)
        if not scan:
            return
        log = self.query_one("#scan-detail", RichLog)
        log.clear()
        log.write(f"[bold]Target:[/bold] {scan.target}")
        log.write(f"[bold]Status:[/bold] {scan.status}")
        log.write(f"[bold]Tools:[/bold] {', '.join(scan.tools_used)}")
        if scan.risk_summary:
            log.write(f"[bold]Risk:[/bold] {scan.risk_summary.risk_level} ({scan.risk_summary.overall_score})")
        log.write(f"\n[bold]Findings ({len(scan.findings)}):[/bold]")
        for f in scan.findings:
            log.write(f"  [{f.severity}] {f.title}")
        if scan.errors:
            log.write(f"\n[bold red]Errors ({len(scan.errors)}):[/bold red]")
            for e in scan.errors:
                log.write(f"  {e.stage}: {e.message}")

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
        row_key = table.get_row_at(table.cursor_row)
        scan_id = row_key[0] if row_key else None
        if not scan_id:
            return
        # Find matching full scan_id
        for sid in self._scan_data:
            if sid.startswith(str(scan_id)):
                report = Path.home() / ".argus-lite" / "scans" / sid / "report" / "report.html"
                if report.exists():
                    webbrowser.open(f"file://{report}")
                    self.notify("Opened in browser")
                else:
                    self.notify("No HTML report found", severity="warning")
                break
