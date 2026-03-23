"""Argus Lite CLI — entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

from argus_lite.core.config import AppConfig, load_config
from argus_lite.core.tool_runner import BaseToolRunner, ToolRegistry
from argus_lite.core.validator import InputSanitizationError, sanitize_target, validate_scope

console = Console()

LEGAL_NOTICE = """\
LEGAL NOTICE: This tool is intended for authorized security testing only.
Always obtain written permission before scanning any system you do not own.
Unauthorized scanning may violate computer crime laws in your jurisdiction.
"""

VERSION = "1.0.0"


def _get_argus_home() -> Path:
    """Get Argus home directory."""
    return Path(os.environ.get("ARGUS_HOME", Path.home() / ".argus-lite"))


def _get_config() -> AppConfig:
    """Load config from default location."""
    home = _get_argus_home()
    return load_config(home / "config.yaml")


def _build_registry(config: AppConfig) -> ToolRegistry:
    """Build tool registry from config — dynamically iterates all tool entries."""
    registry = ToolRegistry()
    # Map config field names to binary names
    _name_map = {"httpx_tool": "httpx"}
    for field_name in config.tools.model_fields:
        entry = getattr(config.tools, field_name, None)
        if entry and entry.enabled:
            bin_name = _name_map.get(field_name, field_name)
            registry.register(BaseToolRunner(name=bin_name, path=str(entry.path)))
    return registry


@click.group()
@click.version_option(version=VERSION, prog_name="argus-lite")
def main() -> None:
    """Argus Lite — local security scanner for authorized penetration testing."""


@main.command()
@click.argument("target")
@click.option("--preset", type=click.Choice(["quick", "full", "recon", "web"]), default="quick")
@click.option("--output", "output_format", type=click.Choice(["json", "md", "html", "sarif"]), default="md")
@click.option("--rate-limit", type=int, default=10, help="Requests per second")
@click.option("--timeout", type=int, default=30, help="Timeout per request (seconds)")
@click.option("--no-confirm", is_flag=True, default=False, help="Skip confirmation prompt")
@click.option("--safe", is_flag=True, default=False, help="Passive checks only")
@click.option("--notify", is_flag=True, default=False, help="Send notifications after scan")
@click.option("--pipeline", "pipeline_path", type=click.Path(exists=True), default=None, help="Custom pipeline YAML")
@click.option("--resume", "resume_id", default=None, help="Resume interrupted scan by scan-id")
@click.option("--templates", multiple=True, help="Custom nuclei template paths")
def scan(
    target: str,
    preset: str,
    output_format: str,
    rate_limit: int,
    timeout: int,
    no_confirm: bool,
    safe: bool,
    notify: bool,
    pipeline_path: str | None,
    resume_id: str | None,
    templates: tuple[str, ...],
) -> None:
    """Scan a target domain or IP address."""
    # Legal notice
    console.print(f"[yellow]{LEGAL_NOTICE}[/yellow]")

    # Step 1: Input sanitization
    try:
        clean_target = sanitize_target(target)
    except InputSanitizationError as e:
        console.print(f"[red]Input sanitization error: {e}[/red]")
        raise SystemExit(1)

    # Step 2: Scope validation
    home = _get_argus_home()
    allowlist_path = home / "allowlist.txt"
    denylist_path = home / "denylist.txt"

    scope = validate_scope(
        clean_target,
        allowlist_path=allowlist_path if allowlist_path.exists() else None,
        denylist_path=denylist_path if denylist_path.exists() else None,
    )

    if not scope.allowed:
        console.print(f"[red]Scope violation: {scope.reason}[/red]")
        raise SystemExit(1)

    for warning in scope.warnings:
        console.print(f"[yellow]Warning: {warning}[/yellow]")

    # Step 3: Confirmation
    if not no_confirm:
        if not click.confirm(f"Scan target '{clean_target}' with preset '{preset}'?"):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return

    # Step 4: Load config and run orchestrator
    import asyncio

    from argus_lite.core.orchestrator import ScanOrchestrator
    from argus_lite.modules.report.html_report import write_html_report
    from argus_lite.modules.report.json_report import write_json_report
    from argus_lite.modules.report.markdown_report import write_markdown_report
    from argus_lite.utils.progress import ScanProgress

    config = _get_config()

    from rich.live import Live
    from rich.table import Table
    from rich.text import Text

    stage_status: dict[str, str] = {}

    def render_progress() -> Table:
        table = Table(show_header=False, box=None, padding=(0, 1))
        for stage, st in stage_status.items():
            if st == "start":
                icon = "[cyan]...[/cyan]"
            elif st == "done":
                icon = "[green]OK[/green]"
            elif st == "fail":
                icon = "[red]FAIL[/red]"
            elif st == "skip":
                icon = "[yellow]SKIP[/yellow]"
            else:
                icon = "[dim]--[/dim]"
            table.add_row(icon, stage)
        return table

    live = Live(render_progress(), console=console, refresh_per_second=4)

    def on_progress(stage: str, status: str) -> None:
        stage_status[stage] = status
        try:
            live.update(render_progress())
        except Exception:
            pass

    from argus_lite.core.resume import load_partial, save_partial

    # Resume logic
    if resume_id:
        home_r = _get_argus_home()
        resume_dir = Path(home_r) / "scans" / resume_id
        partial = load_partial(resume_dir)
        if partial:
            console.print(f"[cyan]Resuming scan {resume_id} (completed: {', '.join(partial.completed_stages)})[/cyan]")
            clean_target = partial.target
        else:
            console.print(f"[red]No partial scan found for {resume_id}[/red]")
            raise SystemExit(1)

    orch = ScanOrchestrator(
        target=clean_target, config=config, on_progress=on_progress,
        preset=preset,
    )

    console.print(f"[bold green]Starting scan: {clean_target} (preset: {preset})[/bold green]")
    console.print()

    with live:
        result = asyncio.get_event_loop().run_until_complete(orch.run())

    console.print()

    # Save partial for resume capability
    home = _get_argus_home()
    scan_dir = Path(home) / "scans" / result.scan_id
    save_partial(result, scan_dir)

    # Generate report
    scan_dir = Path(home) / "scans" / result.scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    report_dir = scan_dir / "report"
    report_dir.mkdir(exist_ok=True)

    from argus_lite.modules.report.sarif_report import write_sarif_report

    writers = {"json": write_json_report, "md": write_markdown_report, "html": write_html_report, "sarif": write_sarif_report}
    ext_map = {"json": "json", "md": "md", "html": "html", "sarif": "sarif"}

    writer = writers[output_format]
    report_path = report_dir / f"report.{ext_map[output_format]}"
    writer(result, report_path)

    # Risk scoring
    from argus_lite.core.risk_scorer import score_scan

    risk = score_scan(result)
    result.risk_summary = risk

    # Re-generate report with risk data
    writer(result, report_path)

    # Display results
    risk_colors = {"NONE": "green", "LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}
    risk_color = risk_colors.get(risk.risk_level, "white")

    console.print(f"\n[bold]Scan {result.status}[/bold]")
    console.print(f"[{risk_color}]Risk: {risk.risk_level} (score: {risk.overall_score})[/{risk_color}]")
    console.print(f"[dim]Report: {report_path}[/dim]")

    if result.errors:
        for err in result.errors:
            console.print(f"[yellow]  Stage '{err.stage}' error: {err.message}[/yellow]")

    # Notifications
    if notify or config.notifications.enabled:
        from argus_lite.core.notifier import NotificationDispatcher

        config.notifications.enabled = True
        dispatcher = NotificationDispatcher(config.notifications)
        if dispatcher.get_active_notifiers():
            asyncio.get_event_loop().run_until_complete(dispatcher.notify_all(result))
            console.print("[dim]Notifications sent[/dim]")


@main.command()
def init() -> None:
    """Initialize Argus Lite configuration."""
    home = _get_argus_home()
    home.mkdir(parents=True, exist_ok=True)

    config_file = home / "config.yaml"
    if config_file.exists():
        console.print(f"[yellow]Config already exists: {config_file}[/yellow]")
        return

    default_config = """\
general:
  log_level: INFO
  log_dir: ~/.argus-lite/logs
  scan_dir: ~/.argus-lite/scans

security:
  require_confirmation: true
  allowlist_only: false
  max_scan_duration_minutes: 120

rate_limits:
  global_rps: 50
  per_target_rps: 10
  concurrent_requests: 5

tools:
  subfinder:
    enabled: true
    path: /usr/bin/subfinder
  naabu:
    enabled: true
    path: /usr/bin/naabu
  nuclei:
    enabled: true
    path: /usr/bin/nuclei
    templates_dir: ~/nuclei-templates
  whatweb:
    enabled: true
    path: /usr/bin/whatweb

api_keys:
  shodan: ""
  virustotal: ""
"""
    config_file.write_text(default_config)
    os.chmod(config_file, 0o600)

    # Create directories
    (home / "logs").mkdir(exist_ok=True)
    (home / "scans").mkdir(exist_ok=True)

    console.print(f"[green]Initialized Argus Lite config at {config_file}[/green]")


@main.command("list")
def list_scans() -> None:
    """List previous scans."""
    home = _get_argus_home()
    scan_dir = home / "scans"

    if not scan_dir.exists():
        console.print("[dim]No scans found.[/dim]")
        return

    scans = sorted(scan_dir.iterdir()) if scan_dir.is_dir() else []
    if not scans:
        console.print("[dim]No scans found.[/dim]")
        return

    for scan_path in scans:
        console.print(f"  {scan_path.name}")


@main.group()
def tools() -> None:
    """Manage external tools."""


@tools.command("check")
def tools_check() -> None:
    """Check availability of external tools."""
    config = _get_config()
    registry = _build_registry(config)
    status = registry.check_all()

    for tool_name, available in status.items():
        icon = "[green]OK[/green]" if available else "[red]MISSING[/red]"
        console.print(f"  {tool_name}: {icon}")

    if not status:
        console.print("[dim]No tools configured.[/dim]")


@main.group()
def config() -> None:
    """View and manage configuration."""


@config.command("show")
def config_show() -> None:
    """Show current configuration."""
    cfg = _get_config()
    console.print(cfg.model_dump_json(indent=2))


@main.group()
def plugins() -> None:
    """Manage plugins."""


@plugins.command("list")
def plugins_list() -> None:
    """List installed plugins."""
    from argus_lite.core.plugin_loader import PluginLoader

    cfg = _get_config()
    loader = PluginLoader([Path(d).expanduser() for d in cfg.plugins.plugin_dirs])
    loaded = loader.load_all()

    if not loaded:
        console.print("[dim]No plugins found.[/dim]")
        return

    for name, plugin in loaded.items():
        console.print(f"  {name} (v{plugin.version}) — stage: {plugin.stage}")


@plugins.command("check")
def plugins_check() -> None:
    """Verify all plugins are loadable."""
    from argus_lite.core.plugin_loader import PluginLoader

    cfg = _get_config()
    loader = PluginLoader([Path(d).expanduser() for d in cfg.plugins.plugin_dirs])
    loaded = loader.load_all()

    if not loaded:
        console.print("[dim]No plugins found.[/dim]")
        return

    for name, plugin in loaded.items():
        avail = plugin.check_available()
        icon = "[green]OK[/green]" if avail else "[red]UNAVAILABLE[/red]"
        console.print(f"  {name}: {icon}")


@main.command()
@click.option("--port", default=8443, help="Dashboard port")
@click.option("--host", default="127.0.0.1", help="Dashboard host")
def dashboard(port: int, host: str) -> None:
    """Launch local web dashboard to browse scan results."""
    try:
        from argus_lite.dashboard.app import create_app
    except ImportError:
        console.print("[red]Flask required. Install: pip install argus-lite[dashboard][/red]")
        raise SystemExit(1)

    home = _get_argus_home()
    app = create_app(str(home))
    console.print(f"[bold green]Argus Dashboard[/bold green] at http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
