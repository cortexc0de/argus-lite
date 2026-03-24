"""OSINT Tab — search Shodan, Censys, ZoomEye, FOFA interactively."""

from __future__ import annotations

import re
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from argus_lite.core.config import AppConfig, load_config
from argus_lite.models.discover import DiscoverQuery
from argus_lite.tui.messages import OsintQueryComplete

_SOURCES = [
    ("All APIs (auto-detect)", "discover"),
    ("Shodan", "shodan"),
    ("Censys", "censys"),
    ("ZoomEye", "zoomeye"),
    ("FOFA", "fofa"),
]

_CSS = """
OsintTab { height: 1fr; }

#osint-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

#osint-controls { height: 3; margin-bottom: 1; }
#osint-source { width: 28; margin-right: 1; }
#osint-input { width: 1fr; margin-right: 1; }
#osint-search { width: 14; }

#osint-results {
    height: 1fr;
    border: round #30363d;
    border-title-color: #58a6ff;
    background: #0d1117;
}

#osint-status {
    color: #8b949e;
    margin-top: 1;
}

#osint-actions { height: 3; margin-top: 1; }
"""


class OsintTab(Static):
    """Interactive OSINT intelligence queries."""

    DEFAULT_CSS = _CSS

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config

    def compose(self) -> ComposeResult:
        yield Label("OSINT INTELLIGENCE", id="osint-title")
        with Horizontal(id="osint-controls"):
            yield Select(_SOURCES, value="discover", id="osint-source", allow_blank=False)
            yield Input(placeholder="CVE-2024-XXXX, WordPress, port:3389, or dork...", id="osint-input")
            yield Button("SEARCH", id="osint-search", variant="primary")
        yield DataTable(id="osint-results")
        yield Label("", id="osint-status")
        with Horizontal(id="osint-actions"):
            yield Button("Save IPs to File", id="save-ips")

    def on_mount(self) -> None:
        table = self.query_one("#osint-results", DataTable)
        table.border_title = "Results"
        table.add_columns("IP", "Port", "Service", "Product", "Country", "Source")
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "osint-search":
            query = self.query_one("#osint-input", Input).value.strip()
            if not query:
                self.notify("Enter a search query", severity="warning")
                return
            source = self.query_one("#osint-source", Select).value
            self._run_search(source, query)
        elif event.button.id == "save-ips":
            self._save_ips()

    @work
    async def _run_search(self, source: str, query: str) -> None:
        from argus_lite.core.discovery_engine import DiscoveryEngine

        config = self._config or load_config(Path.home() / ".argus-lite" / "config.yaml")
        engine = DiscoveryEngine(config)

        self.query_one("#osint-status", Label).update(f"[#00aaff]Searching {source}...[/#00aaff]")

        if source == "discover":
            dq = self._parse_query(query)
            result = await engine.discover(dq)
            hosts = result.hosts
        else:
            method = {
                "shodan": engine._search_shodan,
                "censys": engine._search_censys,
                "zoomeye": engine._search_zoomeye,
                "fofa": engine._search_fofa,
            }.get(source)
            hosts = await method(query) if method else []

        self.post_message(OsintQueryComplete(hosts=hosts))

    def _parse_query(self, query: str) -> DiscoverQuery:
        if re.match(r"CVE-\d{4}-\d+", query, re.IGNORECASE):
            return DiscoverQuery(cve=query)
        if query.isdigit():
            return DiscoverQuery(port=int(query))
        return DiscoverQuery(tech=query)

    def on_osint_query_complete(self, msg: OsintQueryComplete) -> None:
        table = self.query_one("#osint-results", DataTable)
        table.clear()
        for h in msg.hosts:
            table.add_row(
                h.ip, str(h.port) if h.port else "—",
                h.service or "—", h.product or "—",
                h.country or "—", h.source,
            )
        count = len(msg.hosts)
        self.query_one("#osint-status", Label).update(
            f"[bold]{count}[/bold] hosts found" if count else "[#ffaa00]No results[/#ffaa00]"
        )

    def _save_ips(self) -> None:
        table = self.query_one("#osint-results", DataTable)
        if table.row_count == 0:
            self.notify("No results to save", severity="warning")
            return
        ips = []
        for row_key in table.rows:
            row = table.get_row(row_key)
            if row and row[0]:
                ips.append(str(row[0]))
        if ips:
            path = Path.home() / ".argus-lite" / "discover_results.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(ips))
            self.notify(f"{len(ips)} IPs saved to {path}")
