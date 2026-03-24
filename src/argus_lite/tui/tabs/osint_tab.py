"""OSINT Tab — interactive queries across Shodan, Censys, ZoomEye, FOFA."""

from __future__ import annotations

import re
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Input, Select, Static

from argus_lite.core.config import AppConfig, load_config
from argus_lite.models.discover import DiscoverQuery
from argus_lite.tui.messages import OsintQueryComplete

_SOURCES = [
    ("All APIs", "discover"),
    ("Shodan", "shodan"),
    ("Censys", "censys"),
    ("ZoomEye", "zoomeye"),
    ("FOFA", "fofa"),
]


class OsintTab(Static):
    """Interactive OSINT queries and vulnerability discovery."""

    DEFAULT_CSS = """
    OsintTab { height: 100%; }
    #osint-controls { height: 3; margin-bottom: 1; }
    #osint-source { width: 18; }
    #osint-input { width: 1fr; }
    #osint-search { width: 14; }
    #osint-results { height: 1fr; }
    #osint-actions { height: 3; margin-top: 1; }
    """

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config

    def compose(self) -> ComposeResult:
        with Horizontal(id="osint-controls"):
            yield Select(_SOURCES, value="discover", id="osint-source", allow_blank=False)
            yield Input(placeholder="CVE, tech, service, or dork...", id="osint-input")
            yield Button("Search", id="osint-search", variant="primary")
        yield DataTable(id="osint-results")
        with Horizontal(id="osint-actions"):
            yield Button("Save IPs", id="save-ips")
            yield Button("Bulk Scan", id="send-bulk")

    def on_mount(self) -> None:
        table = self.query_one("#osint-results", DataTable)
        table.add_columns("IP", "Port", "Service", "Product", "Country", "Org", "Source")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "osint-search":
            query = self.query_one("#osint-input", Input).value.strip()
            if not query:
                self.notify("Enter a query", severity="warning")
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

        self.notify(f"Querying {source}...", severity="information")

        if source == "discover":
            dq = self._parse_query(query)
            result = await engine.discover(dq)
            hosts = result.hosts
        else:
            # Direct platform query
            method = {
                "shodan": engine._search_shodan,
                "censys": engine._search_censys,
                "zoomeye": engine._search_zoomeye,
                "fofa": engine._search_fofa,
            }.get(source)
            if method:
                hosts = await method(query)
            else:
                hosts = []

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
                h.country or "—", h.org or "—", h.source)
        self.notify(f"{len(msg.hosts)} hosts found")

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
