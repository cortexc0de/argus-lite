"""Scan Tab — target input, preset selector, live progress, findings."""

from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Label, RichLog, Select, Static

from argus_lite.core.config import AppConfig
from argus_lite.models.finding import Finding
from argus_lite.tui.messages import FindingUpdate, ScanComplete, StageUpdate

_PRESETS = [
    ("Quick (DNS + headers + SSL)", "quick"),
    ("Full (all tools)", "full"),
    ("Web (httpx + nuclei + katana)", "web"),
    ("Recon only (passive)", "recon"),
    ("Bulk (fast per-host)", "bulk"),
]

_STAGE_ICONS = {"start": "⟳", "done": "✓", "fail": "✗", "skip": "—"}


class ScanTab(Static):
    """Tab for running scans with live progress."""

    DEFAULT_CSS = """
    ScanTab { height: 100%; }
    #scan-controls { height: 3; margin-bottom: 1; }
    #scan-target { width: 1fr; }
    #scan-preset { width: 20; }
    #scan-start { width: 16; }
    #scan-body { height: 1fr; }
    #scan-stages { width: 30; border: round #00ff41; padding: 0 1; }
    #scan-findings { width: 1fr; border: round #ff6b6b; }
    """

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config or AppConfig()
        self._scanning = False

    def compose(self) -> ComposeResult:
        with Horizontal(id="scan-controls"):
            yield Input(placeholder="Target (domain or IP)", id="scan-target")
            yield Select(_PRESETS, value="quick", id="scan-preset", allow_blank=False)
            yield Button("Scan", id="scan-start", variant="success")
        with Horizontal(id="scan-body"):
            yield RichLog(id="scan-stages", highlight=True)
            yield DataTable(id="scan-findings")

    def on_mount(self) -> None:
        table = self.query_one("#scan-findings", DataTable)
        table.add_columns("Sev", "Title", "Asset", "Source")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-start" and not self._scanning:
            target = self.query_one("#scan-target", Input).value.strip()
            if not target:
                self.notify("Enter a target", severity="warning")
                return
            self._start_scan(target)

    @work
    async def _start_scan(self, target: str) -> None:
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.risk_scorer import score_scan

        self._scanning = True
        btn = self.query_one("#scan-start", Button)
        btn.disabled = True
        btn.label = "Scanning..."

        log = self.query_one("#scan-stages", RichLog)
        log.clear()
        self.query_one("#scan-findings", DataTable).clear()
        log.write(f"[bold cyan]Target:[/bold cyan] {target}")

        preset = self.query_one("#scan-preset", Select).value

        def on_progress(stage: str, status: str) -> None:
            self.app.post_message(StageUpdate(stage=stage, status=status))

        def on_finding(finding: Finding) -> None:
            self.app.post_message(FindingUpdate(finding=finding))

        orch = ScanOrchestrator(
            target=target,
            config=self._config,
            preset=preset,
            on_progress=on_progress,
            on_finding=on_finding,
        )
        result = await orch.run()
        result.risk_summary = score_scan(result)

        # Save result
        from argus_lite.core.resume import save_partial
        home = Path.home() / ".argus-lite" / "scans" / result.scan_id
        save_partial(result, home)

        self.app.post_message(ScanComplete(result=result))

        self._scanning = False
        btn.disabled = False
        btn.label = "Scan"

    def on_stage_update(self, msg: StageUpdate) -> None:
        icon = _STAGE_ICONS.get(msg.status, "?")
        colors = {"start": "cyan", "done": "green", "fail": "red", "skip": "yellow"}
        c = colors.get(msg.status, "white")
        self.query_one("#scan-stages", RichLog).write(f"[{c}]{icon}[/{c}] {msg.stage}")

    def on_finding_update(self, msg: FindingUpdate) -> None:
        f = msg.finding
        self.query_one("#scan-findings", DataTable).add_row(
            f.severity, f.title, f.asset, f.source)

    def on_scan_complete(self, msg: ScanComplete) -> None:
        log = self.query_one("#scan-stages", RichLog)
        r = msg.result
        risk = r.risk_summary.risk_level if r.risk_summary else "NONE"
        rc = {"NONE": "green", "LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk, "white")
        log.write("")
        log.write(f"[bold green]✓ Complete[/bold green]")
        log.write(f"[{rc}]Risk: {risk}[/{rc}] | Findings: {len(r.findings)}")
        if r.tools_used:
            log.write(f"[dim]Tools: {', '.join(r.tools_used)}[/dim]")
        self.notify(f"Scan complete — {risk}", severity="information")
