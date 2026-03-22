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
    """Build tool registry from config."""
    registry = ToolRegistry()
    for tool_name in ("subfinder", "naabu", "nuclei", "whatweb"):
        entry = getattr(config.tools, tool_name, None)
        if entry and entry.enabled:
            registry.register(BaseToolRunner(name=tool_name, path=str(entry.path)))
    return registry


@click.group()
@click.version_option(version=VERSION, prog_name="argus-lite")
def main() -> None:
    """Argus Lite — local security scanner for authorized penetration testing."""


@main.command()
@click.argument("target")
@click.option("--preset", type=click.Choice(["quick", "full", "recon", "web"]), default="quick")
@click.option("--output", "output_format", type=click.Choice(["json", "md", "html"]), default="md")
@click.option("--rate-limit", type=int, default=10, help="Requests per second")
@click.option("--timeout", type=int, default=30, help="Timeout per request (seconds)")
@click.option("--no-confirm", is_flag=True, default=False, help="Skip confirmation prompt")
@click.option("--safe", is_flag=True, default=False, help="Passive checks only")
def scan(
    target: str,
    preset: str,
    output_format: str,
    rate_limit: int,
    timeout: int,
    no_confirm: bool,
    safe: bool,
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
    progress = ScanProgress(stages=["recon", "analysis"])

    def on_progress(stage: str, status: str) -> None:
        if status == "start":
            console.print(f"[cyan]  Running {stage}...[/cyan]")
        elif status == "done":
            console.print(f"[green]  {stage} completed[/green]")
        elif status == "fail":
            console.print(f"[red]  {stage} failed[/red]")
        elif status == "skip":
            console.print(f"[yellow]  {stage} skipped[/yellow]")

    orch = ScanOrchestrator(
        target=clean_target, config=config, on_progress=on_progress,
    )

    console.print(f"[bold green]Starting scan: {clean_target} (preset: {preset})[/bold green]")
    result = asyncio.get_event_loop().run_until_complete(orch.run())

    # Generate report
    home = _get_argus_home()
    scan_dir = Path(home) / "scans" / result.scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    report_dir = scan_dir / "report"
    report_dir.mkdir(exist_ok=True)

    writers = {"json": write_json_report, "md": write_markdown_report, "html": write_html_report}
    ext_map = {"json": "json", "md": "md", "html": "html"}

    writer = writers[output_format]
    report_path = report_dir / f"report.{ext_map[output_format]}"
    writer(result, report_path)

    console.print(f"\n[bold]Scan {result.status}[/bold]")
    console.print(f"[dim]Report: {report_path}[/dim]")

    if result.errors:
        for err in result.errors:
            console.print(f"[yellow]  Stage '{err.stage}' error: {err.message}[/yellow]")


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


if __name__ == "__main__":
    main()
