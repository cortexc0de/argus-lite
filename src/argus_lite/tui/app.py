"""Argus interactive TUI — real-time scan dashboard."""

from __future__ import annotations

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Header, Log

from argus_lite.core.config import AppConfig
from argus_lite.models.finding import Finding
from argus_lite.models.scan import ScanResult
from argus_lite.tui.messages import FindingUpdate, ScanComplete, StageUpdate

_STAGE_ICONS = {
    "start": "⟳",
    "done": "✓",
    "fail": "✗",
    "skip": "—",
}

CSS = """
Screen {
    layout: grid;
    grid-size: 2;
    grid-gutter: 1 2;
}
#stages {
    height: 100%;
    border: round #00ff41;
}
#findings {
    height: 100%;
    border: round #ff6b6b;
}
"""


class ArgusApp(App):
    """Interactive TUI for Argus security scans."""

    BINDINGS = [("q", "quit", "Quit")]
    CSS = CSS

    def __init__(
        self,
        target: str,
        config: AppConfig,
        preset: str = "quick",
        rate_limit: int = 10,
        timeout: int = 30,
        safe: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._target = target
        self._config = config
        self._preset = preset
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._safe = safe
        self._result: ScanResult | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Log(id="stages", highlight=True, markup=True)
        yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Argus — {self._target}"
        self.sub_title = f"preset: {self._preset}"
        table = self.query_one("#findings", DataTable)
        table.add_columns("Severity", "Title", "Asset", "Source")
        self.run_scan()

    @work
    async def run_scan(self) -> None:
        from argus_lite.core.orchestrator import ScanOrchestrator

        orch = ScanOrchestrator(
            target=self._target,
            config=self._config,
            preset=self._preset,
            on_progress=self._on_progress,
            on_finding=self._on_finding,
        )
        result = await orch.run()
        self.post_message(ScanComplete(result=result))

    def _on_progress(self, stage: str, status: str) -> None:
        self.post_message(StageUpdate(stage=stage, status=status))

    def _on_finding(self, finding: Finding) -> None:
        self.post_message(FindingUpdate(finding=finding))

    def on_stage_update(self, msg: StageUpdate) -> None:
        icon = _STAGE_ICONS.get(msg.status, "?")
        color_map = {
            "start": "cyan",
            "done": "green",
            "fail": "red",
            "skip": "yellow",
        }
        color = color_map.get(msg.status, "white")
        log = self.query_one("#stages", Log)
        log.write_line(f"[{color}]{icon}[/{color}] {msg.stage}")

    def on_finding_update(self, msg: FindingUpdate) -> None:
        table = self.query_one("#findings", DataTable)
        f = msg.finding
        table.add_row(f.severity, f.title, f.asset, f.source)

    def on_scan_complete(self, msg: ScanComplete) -> None:
        self._result = msg.result
        log = self.query_one("#stages", Log)
        log.write_line(f"[bold green]✓ Scan complete[/bold green]")
        # Don't auto-exit — let user review and press Q
