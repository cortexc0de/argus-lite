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
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI analysis of results")
@click.option("--tui", is_flag=True, default=False, help="Interactive TUI mode (requires textual)")
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
    use_ai: bool,
    tui: bool,
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

    # TUI mode
    if tui:
        try:
            from argus_lite.tui.app import ArgusApp
        except ImportError:
            console.print("[red]textual required for TUI. Install: pip install argus-lite[/red]")
            raise SystemExit(1)

        app = ArgusApp(
            target=clean_target,
            config=config,
            preset=preset,
            rate_limit=rate_limit,
            timeout=timeout,
            safe=safe,
        )
        app.run()
        result = app._result
        if result is None:
            raise SystemExit(0)
    else:
        from rich.live import Live
        from rich.table import Table

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

    # AI Analysis (optional)
    if use_ai or config.ai.enabled:
        from argus_lite.core.ai_analyzer import AIAnalyzer

        if config.ai.api_key:
            console.print("[cyan]Running AI analysis...[/cyan]")
            analyzer = AIAnalyzer(config.ai)
            ai_result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(result))
            result.ai_analysis = ai_result
            if ai_result.executive_summary:
                console.print(f"[green]AI analysis complete ({ai_result.model_used}, {ai_result.tokens_used} tokens)[/green]")
            else:
                console.print("[yellow]AI analysis returned no results[/yellow]")
        else:
            console.print("[yellow]AI enabled but no API key set (ARGUS_AI_KEY)[/yellow]")

    # Re-generate report with risk + AI data
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


@main.command("run")
@click.argument("template_path", type=click.Path(exists=True))
@click.option("--target", default=None, help="Override target defined in template")
@click.pass_context
def run_template(ctx: click.Context, template_path: str, target: str | None) -> None:
    """Run a scan from a YAML template file.

    Example: argus run examples/quick_scan.yaml --target example.com
    """
    from argus_lite.core.scan_template import load_scan_template

    tmpl = load_scan_template(template_path)
    effective_target = target or tmpl.target

    ctx.invoke(
        scan,
        target=effective_target,
        preset=tmpl.preset,
        output_format=tmpl.report.format,
        rate_limit=tmpl.rate_limit,
        timeout=tmpl.timeout,
        no_confirm=tmpl.no_confirm,
        safe=False,
        notify=any([tmpl.notify.telegram, tmpl.notify.discord, tmpl.notify.slack]),
        pipeline_path=None,
        resume_id=None,
        templates=(),
        use_ai=tmpl.ai.enabled,
        tui=False,
    )


@main.command("bulk")
@click.argument("sources", nargs=-1)
@click.option("--shodan", "shodan_query", default=None, help="Shodan search query (requires ARGUS_SHODAN_KEY)")
@click.option("--preset", type=click.Choice(["bulk", "quick", "web", "full", "recon"]), default="bulk",
              help="Scan preset for each target")
@click.option("--concurrency", type=int, default=5, help="Max parallel scans")
@click.option("--max-targets", type=int, default=50, help="Maximum targets to scan")
@click.option("--output", "output_format", type=click.Choice(["json", "md", "html", "sarif"]), default="html")
@click.option("--no-confirm", is_flag=True, default=False, help="Skip confirmation prompt")
def bulk_scan(
    sources: tuple[str, ...],
    shodan_query: str | None,
    preset: str,
    concurrency: int,
    max_targets: int,
    output_format: str,
    no_confirm: bool,
) -> None:
    """Bulk scan multiple targets: files, CIDRs, ASNs, or Shodan queries.

    \b
    Examples:
      argus bulk targets.txt
      argus bulk 192.168.1.0/24
      argus bulk AS12345
      argus bulk targets.txt 10.0.1.0/24 --preset web
      argus bulk --shodan "org:MyCompany" --concurrency 3

    Generates individual reports per target + a combined summary.html.
    IMPORTANT: Only scan systems you have written permission to test.
    """
    import asyncio
    from pathlib import Path

    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

    from argus_lite.core.bulk_scanner import BulkScanner
    from argus_lite.core.target_expander import TargetExpander
    from argus_lite.modules.report.bulk_report import write_bulk_report
    from argus_lite.modules.report.html_report import write_html_report
    from argus_lite.modules.report.json_report import write_json_report
    from argus_lite.modules.report.markdown_report import write_markdown_report
    from argus_lite.modules.report.sarif_report import write_sarif_report

    console.print(f"[yellow]{LEGAL_NOTICE}[/yellow]")

    config = _get_config()
    config.bulk.max_concurrent = concurrency
    config.bulk.max_targets = max_targets

    # Build source list
    all_sources = list(sources)
    if shodan_query:
        # Shodan handled via expand_shodan() separately
        all_sources_for_expand = list(sources)
    else:
        all_sources_for_expand = all_sources

    if not all_sources_for_expand and not shodan_query:
        console.print("[red]No sources provided. Use positional args or --shodan.[/red]")
        raise SystemExit(1)

    # Expand targets
    expander = TargetExpander(config)
    if shodan_query:
        targets = asyncio.get_event_loop().run_until_complete(expander.expand_shodan(shodan_query))
        targets += asyncio.get_event_loop().run_until_complete(expander.expand(list(sources)))
    else:
        targets = asyncio.get_event_loop().run_until_complete(expander.expand(all_sources_for_expand))

    # Deduplicate & cap
    seen: set[str] = set()
    unique_targets: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
        if len(unique_targets) >= max_targets:
            break

    if not unique_targets:
        console.print("[red]No valid targets found after expansion.[/red]")
        raise SystemExit(1)

    console.print(f"[bold green]Bulk scan: {len(unique_targets)} targets | preset: {preset}[/bold green]")
    console.print()

    if not no_confirm:
        if not click.confirm(f"Scan {len(unique_targets)} targets with preset '{preset}'?"):
            console.print("[yellow]Bulk scan cancelled.[/yellow]")
            return

    # Setup output directory
    home = _get_argus_home()
    import uuid as _uuid
    bulk_id_short = str(_uuid.uuid4())[:8]
    bulk_dir = Path(home) / "scans" / f"bulk-{bulk_id_short}"
    bulk_dir.mkdir(parents=True, exist_ok=True)

    # Progress tracking
    completed = [0]
    failed_list: list[str] = []
    writers = {"json": write_json_report, "md": write_markdown_report,
               "html": write_html_report, "sarif": write_sarif_report}
    ext_map = {"json": "json", "md": "md", "html": "html", "sarif": "sarif"}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(unique_targets))

        def on_done(target: str, result) -> None:
            # Write individual report
            target_dir = bulk_dir / target.replace("/", "_").replace(":", "_")
            target_dir.mkdir(parents=True, exist_ok=True)
            report_path = target_dir / f"report.{ext_map[output_format]}"
            writers[output_format](result, report_path)
            completed[0] += 1
            progress.advance(task)
            progress.update(task, description=f"[green]✓[/green] {target}")

        def on_fail(target: str, err: str) -> None:
            failed_list.append(target)
            progress.advance(task)
            progress.update(task, description=f"[red]✗[/red] {target}")

        scanner = BulkScanner(
            config=config,
            preset=preset,
            concurrency=concurrency,
            on_target_done=on_done,
            on_target_fail=on_fail,
        )
        bulk_result = asyncio.get_event_loop().run_until_complete(scanner.run(unique_targets))

    # Write combined summary report
    write_bulk_report(bulk_result, bulk_dir)

    console.print()
    s = bulk_result.summary
    risk_colors = {"NONE": "green", "LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}
    risk_color = risk_colors.get(s.highest_risk, "white")
    console.print(f"[bold]Bulk scan complete[/bold]")
    console.print(f"  Targets: {s.total_targets} | Completed: {s.completed} | Failed: {s.failed}")
    console.print(f"  Live hosts: {s.live_hosts} | Findings: {s.total_findings} | CVEs: {s.total_vulnerabilities}")
    console.print(f"  [{risk_color}]Highest risk: {s.highest_risk}[/{risk_color}]")
    console.print(f"  [dim]Summary: {bulk_dir}/summary.html[/dim]")


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
