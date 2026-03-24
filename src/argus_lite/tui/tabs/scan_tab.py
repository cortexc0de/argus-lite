"""Scan Tab — target input, preset selector, live progress, findings."""

from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Input, Label, ProgressBar, RichLog, Select, Static

from argus_lite.core.config import AppConfig
from argus_lite.models.finding import Finding
from argus_lite.tui.messages import FindingUpdate, ScanComplete, StageUpdate

_PRESETS = [
    ("Quick — DNS, headers, SSL", "quick"),
    ("Full — all 15 tools", "full"),
    ("Web — httpx, nuclei, katana", "web"),
    ("Recon — passive only", "recon"),
    ("Bulk — fast per-host", "bulk"),
]

_STAGE_ICONS = {"start": "⟳", "done": "✓", "fail": "✗", "skip": "—"}

_CSS = """
ScanTab {
    height: 1fr;
}

#scan-header {
    height: auto;
    background: #1a1f2e;
    border: round #30363d;
    padding: 1 2;
    margin-bottom: 1;
}

#scan-header Label {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

#scan-controls {
    height: 3;
    margin-bottom: 1;
}

#scan-target {
    width: 1fr;
    margin-right: 1;
}

#scan-preset {
    width: 35;
    margin-right: 1;
}

#scan-start {
    width: 14;
    min-width: 14;
}

#scan-body {
    height: 1fr;
}

#scan-left {
    width: 35;
    margin-right: 1;
}

#scan-stages {
    height: 1fr;
    border: round #30363d;
    border-title-color: #00ff41;
    background: #0d1117;
    padding: 0 1;
}

#scan-right {
    width: 1fr;
}

#scan-findings {
    height: 1fr;
    border: round #30363d;
    border-title-color: #ff6b6b;
    background: #0d1117;
}

#scan-summary {
    height: auto;
    background: #1a1f2e;
    border: round #30363d;
    padding: 1 2;
    margin-top: 1;
    display: none;
}

#scan-summary.visible {
    display: block;
}
"""


class ScanTab(Static):
    """Target scanning with live progress and findings."""

    DEFAULT_CSS = _CSS

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config or AppConfig()
        self._scanning = False
        self._stage_count = 0

    def compose(self) -> ComposeResult:
        with Vertical(id="scan-header"):
            yield Label("TARGET SCAN")
            with Horizontal(id="scan-controls"):
                yield Input(
                    placeholder="Enter target — domain, IP, or URL",
                    id="scan-target",
                )
                yield Select(
                    _PRESETS, value="quick", id="scan-preset", allow_blank=False,
                )
                yield Button("SCAN", id="scan-start", variant="success")

        with Horizontal(id="scan-body"):
            with Vertical(id="scan-left"):
                yield RichLog(id="scan-stages", highlight=True)
            with Vertical(id="scan-right"):
                yield DataTable(id="scan-findings")

        with Vertical(id="scan-summary"):
            yield Label(id="summary-text")

    def on_mount(self) -> None:
        stages = self.query_one("#scan-stages", RichLog)
        stages.border_title = "Progress"
        stages.write("[dim]Ready. Enter target and press SCAN.[/dim]")

        table = self.query_one("#scan-findings", DataTable)
        table.border_title = "Findings"
        table.add_columns("Sev", "Title", "Source")
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-start" and not self._scanning:
            target = self.query_one("#scan-target", Input).value.strip()
            if not target:
                self.notify("Enter a target first", severity="warning")
                return
            self._start_scan(target)

    @work
    async def _start_scan(self, target: str) -> None:
        from argus_lite.core.orchestrator import ScanOrchestrator
        from argus_lite.core.risk_scorer import score_scan

        self._scanning = True
        self._stage_count = 0
        btn = self.query_one("#scan-start", Button)
        btn.disabled = True
        btn.label = "SCANNING..."

        log = self.query_one("#scan-stages", RichLog)
        log.clear()
        self.query_one("#scan-findings", DataTable).clear()

        log.write(f"[bold #00ff41]Target:[/bold #00ff41] {target}")
        preset = self.query_one("#scan-preset", Select).value
        log.write(f"[bold #00ff41]Preset:[/bold #00ff41] {preset}")
        log.write("[dim]─" * 30 + "[/dim]")

        # Hide summary from previous scan
        summary = self.query_one("#scan-summary")
        summary.remove_class("visible")

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

        from argus_lite.core.resume import save_partial
        home = Path.home() / ".argus-lite" / "scans" / result.scan_id
        save_partial(result, home)

        self.app.post_message(ScanComplete(result=result))
        self._scanning = False
        btn.disabled = False
        btn.label = "SCAN"

    def on_stage_update(self, msg: StageUpdate) -> None:
        icon = _STAGE_ICONS.get(msg.status, "?")
        colors = {"start": "#00aaff", "done": "#00ff41", "fail": "#ff4444", "skip": "#ffaa00"}
        c = colors.get(msg.status, "white")
        self._stage_count += 1 if msg.status == "done" else 0
        self.query_one("#scan-stages", RichLog).write(
            f"[{c}]{icon}[/{c}] [bold]{msg.stage}[/bold]"
        )

    def on_finding_update(self, msg: FindingUpdate) -> None:
        f = msg.finding
        sev_color = "#00ff41" if f.severity == "INFO" else "#ffaa00"
        self.query_one("#scan-findings", DataTable).add_row(
            f.severity, f.title[:60], f.source)

    def on_scan_complete(self, msg: ScanComplete) -> None:
        log = self.query_one("#scan-stages", RichLog)
        r = msg.result
        risk = r.risk_summary.risk_level if r.risk_summary else "NONE"
        score = r.risk_summary.overall_score if r.risk_summary else 0
        rc = {"NONE": "#00ff41", "LOW": "#00aaff", "MEDIUM": "#ffaa00", "HIGH": "#ff4444"}.get(risk, "white")

        log.write("")
        log.write("[dim]─" * 30 + "[/dim]")
        log.write(f"[bold #00ff41]✓ SCAN COMPLETE[/bold #00ff41]")
        log.write(f"[{rc}]Risk: {risk} ({score})[/{rc}]")
        log.write(f"Findings: {len(r.findings)}")
        log.write(f"Tools: {len(r.tools_used)}")

        # Show summary panel
        summary = self.query_one("#scan-summary")
        summary.add_class("visible")
        summary_text = self.query_one("#summary-text", Label)
        tools = ", ".join(r.tools_used[:8])
        if len(r.tools_used) > 8:
            tools += f" +{len(r.tools_used) - 8}"
        summary_text.update(
            f"[bold]Risk:[/bold] [{rc}]{risk} ({score})[/{rc}]  "
            f"[bold]Findings:[/bold] {len(r.findings)}  "
            f"[bold]Tools:[/bold] {tools}"
        )

        self.notify(f"Scan complete — {risk} ({score})", severity="information")
