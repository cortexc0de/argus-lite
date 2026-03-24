"""Scan orchestrator — main coordinator for all scan stages."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from argus_lite.core.concurrent import run_parallel
from argus_lite.core.config import AppConfig
from argus_lite.core.tool_runner import BaseToolRunner, ToolNotFoundError
from argus_lite.models.analysis import AnalysisResult
from argus_lite.models.finding import Finding
from argus_lite.models.recon import ReconResult
from argus_lite.models.scan import ScanResult, StageError

logger = logging.getLogger(__name__)

# Preset -> tool sets
PRESETS: dict[str, dict[str, list[str]]] = {
    "quick": {
        "recon": ["dns", "whois", "certificates"],
        "analysis": ["headers", "techstack", "ssl"],
    },
    "full": {
        "recon": ["dns", "whois", "subdomains", "certificates", "httpx", "katana", "gau", "dnsx", "tlsx", "screenshots"],
        "analysis": ["ports", "techstack", "headers", "ssl", "nuclei", "ffuf"],
    },
    "recon": {
        "recon": ["dns", "whois", "subdomains", "certificates", "dnsx", "tlsx", "gau"],
        "analysis": [],
    },
    "web": {
        "recon": ["dns", "certificates", "httpx", "katana", "screenshots"],
        "analysis": ["headers", "ssl", "techstack", "nuclei"],
    },
    "bulk": {
        "recon": ["dns", "httpx"],
        "analysis": ["techstack", "headers", "nuclei"],
    },
}


class ScanOrchestrator:
    """Coordinates scan stages: recon -> analysis -> report."""

    def __init__(
        self,
        target: str,
        config: AppConfig,
        on_progress: Callable[[str, str], None] | None = None,
        preset: str = "quick",
        on_finding: Callable[[Finding], None] | None = None,
        skip_cve: bool = False,
    ) -> None:
        self.target = target
        self.config = config
        self.shutdown_requested = False
        self._on_progress = on_progress or (lambda stage, status: None)
        self._on_finding = on_finding
        # Skip CVE if explicitly requested, or for bulk/recon presets (speed)
        self._skip_cve = skip_cve or preset in ("bulk", "recon")
        self._scan_id = str(uuid.uuid4())
        self._preset = preset
        self._tools_used: list[str] = []
        self._errors: list[StageError] = []
        self._completed_stages: list[str] = []
        self._skipped_stages: list[str] = []
        self._recon_result = ReconResult()
        self._analysis_result = AnalysisResult()
        self._findings: list[Finding] = []
        self._vulnerabilities: list = []

    def get_enabled_tools(self) -> set[str]:
        """Get all tool names enabled for the current preset."""
        preset_def = PRESETS.get(self._preset, PRESETS["quick"])
        tools: set[str] = set()
        # Map subtask names to tool binary names
        _SUBTASK_TO_TOOL = {
            "dns": "dig", "whois": "whois", "subdomains": "subfinder",
            "certificates": "openssl", "httpx": "httpx", "katana": "katana",
            "gau": "gau", "dnsx": "dnsx", "tlsx": "tlsx",
            "ports": "naabu", "techstack": "whatweb", "headers": "headers",
            "ssl": "ssl_check", "nuclei": "nuclei", "ffuf": "ffuf",
            "screenshots": "gowitness",
        }
        for stage_tools in preset_def.values():
            for subtask in stage_tools:
                tool = _SUBTASK_TO_TOOL.get(subtask, subtask)
                tools.add(tool)
        return tools

    def _is_enabled(self, subtask: str) -> bool:
        """Check if a subtask is enabled in current preset."""
        preset_def = PRESETS.get(self._preset, PRESETS["quick"])
        for stage_tools in preset_def.values():
            if subtask in stage_tools:
                return True
        return False

    def request_shutdown(self) -> None:
        self.shutdown_requested = True

    async def run(self) -> ScanResult:
        started_at = datetime.now(tz=timezone.utc)

        await self._execute_stage("recon", self._run_recon)

        if not self.shutdown_requested:
            await self._execute_stage("analysis", self._run_analysis)
        else:
            self._skipped_stages.append("analysis")
            self._on_progress("analysis", "skip")

        if not self.shutdown_requested and not self._skip_cve:
            await self._execute_stage("cve_enrichment", self._run_cve_enrichment)
        elif self._skip_cve:
            self._skipped_stages.append("cve_enrichment")

        # Run plugins (if any loaded)
        if not self.shutdown_requested and self.config.plugins.enabled:
            await self._run_plugins()

        completed_at = datetime.now(tz=timezone.utc)
        status = "interrupted" if self.shutdown_requested else "completed"

        return ScanResult(
            scan_id=self._scan_id,
            target=self.target,
            target_type="domain",
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            recon=self._recon_result,
            analysis=self._analysis_result,
            findings=self._findings,
            vulnerabilities=self._vulnerabilities,
            tools_used=self._tools_used,
            completed_stages=self._completed_stages,
            skipped_stages=self._skipped_stages,
            errors=self._errors,
        )

    async def _execute_stage(self, name: str, func: Callable) -> None:
        self._on_progress(name, "start")
        try:
            await func()
            self._completed_stages.append(name)
            self._on_progress(name, "done")
        except Exception as e:
            self._errors.append(
                StageError(
                    stage=name, error_type=type(e).__name__,
                    message=str(e), timestamp=datetime.now(tz=timezone.utc),
                )
            )
            self._on_progress(name, "fail")

    async def _run_subtask(self, name: str, coro) -> None:
        if self.shutdown_requested:
            return
        try:
            await coro
        except ToolNotFoundError as e:
            logger.warning("Tool not found for subtask '%s', skipping", name)
            self._skipped_stages.append(name)
            self._on_progress(name, "skip")
        except Exception as e:
            logger.warning("Subtask '%s' failed: %s", name, e)
            self._errors.append(
                StageError(
                    stage=name, error_type=type(e).__name__,
                    message=str(e), timestamp=datetime.now(tz=timezone.utc),
                )
            )
            self._on_progress(name, "fail")

    async def _run_recon(self) -> None:
        from argus_lite.modules.recon.censys_api import censys_lookup
        from argus_lite.modules.recon.certificates import certificate_info
        from argus_lite.modules.recon.dns import dns_enumerate
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output
        from argus_lite.modules.recon.fofa_api import fofa_lookup
        from argus_lite.modules.recon.gau_urls import gau_discover
        from argus_lite.modules.recon.gowitness import gowitness_capture
        from argus_lite.modules.recon.greynoise_api import greynoise_lookup
        from argus_lite.modules.recon.httpx_probe import httpx_probe, httpx_probe_multi
        from argus_lite.modules.recon.katana_crawl import katana_crawl
        from argus_lite.modules.recon.securitytrails_api import st_lookup
        from argus_lite.modules.recon.shodan_api import shodan_lookup
        from argus_lite.modules.recon.subdomains import subdomain_enumerate
        from argus_lite.modules.recon.tlsx_certs import tlsx_scan
        from argus_lite.modules.recon.virustotal_api import vt_lookup
        from argus_lite.modules.recon.whois import whois_lookup
        from argus_lite.modules.recon.zoomeye_api import zoomeye_lookup

        # Group 0: OSINT APIs (no tools needed, run in parallel)
        api_tasks = []
        api_keys = self.config.api_keys

        if api_keys.shodan:
            async def do_shodan():
                self._recon_result.shodan_info = await shodan_lookup(self.target, api_keys.shodan)
                self._tools_used.append("shodan-api")
            api_tasks.append(do_shodan())

        if api_keys.virustotal:
            async def do_vt():
                self._recon_result.virustotal_info = await vt_lookup(self.target, api_keys.virustotal)
                self._tools_used.append("virustotal-api")
            api_tasks.append(do_vt())

        if api_keys.censys_api_id and api_keys.censys_api_secret:
            async def do_censys():
                self._recon_result.censys_info = await censys_lookup(
                    self.target, api_id=api_keys.censys_api_id, api_secret=api_keys.censys_api_secret)
                self._tools_used.append("censys-api")
            api_tasks.append(do_censys())

        if api_keys.zoomeye_api_key:
            async def do_zoomeye():
                self._recon_result.zoomeye_info = await zoomeye_lookup(
                    self.target, api_key=api_keys.zoomeye_api_key)
                self._tools_used.append("zoomeye-api")
            api_tasks.append(do_zoomeye())

        if api_keys.fofa_email and api_keys.fofa_api_key:
            async def do_fofa():
                self._recon_result.fofa_info = await fofa_lookup(
                    self.target, email=api_keys.fofa_email, api_key=api_keys.fofa_api_key)
                self._tools_used.append("fofa-api")
            api_tasks.append(do_fofa())

        # GreyNoise: enriches the main target IP (works even without API key via community endpoint)
        async def do_greynoise():
            self._recon_result.greynoise_info = await greynoise_lookup(
                self.target, api_key=api_keys.greynoise_api_key)
            self._tools_used.append("greynoise-api")
        api_tasks.append(do_greynoise())

        async def do_st():
            import os
            st_key = os.environ.get("ARGUS_SECURITYTRAILS_KEY", "")
            if st_key:
                self._recon_result.securitytrails_info = await st_lookup(self.target, st_key)
                self._tools_used.append("securitytrails-api")
        api_tasks.append(do_st())

        if api_tasks:
            await run_parallel(api_tasks)

        # Group 1: Independent passive recon (run in parallel)
        group1 = []

        if self._is_enabled("dns"):
            async def do_dns():
                runner = self._make_runner("dig", "/usr/bin/dig")
                self._recon_result.dns_records = await dns_enumerate(self.target, runner=runner)
                self._tools_used.append("dig")
            group1.append(self._run_subtask("dns", do_dns()))

        if self._is_enabled("whois"):
            async def do_whois():
                runner = self._make_runner("whois", "/usr/bin/whois")
                self._recon_result.whois_info = await whois_lookup(self.target, runner=runner)
                self._tools_used.append("whois")
            group1.append(self._run_subtask("whois", do_whois()))

        if self._is_enabled("subdomains"):
            async def do_subdomains():
                cfg = self.config.tools.subfinder
                if not cfg.enabled:
                    return
                runner = self._make_runner("subfinder", str(cfg.path))
                self._recon_result.subdomains = await subdomain_enumerate(self.target, runner=runner)
                self._tools_used.append("subfinder")
            group1.append(self._run_subtask("subdomains", do_subdomains()))

        if self._is_enabled("certificates"):
            async def do_certs():
                runner = self._make_runner("openssl", "/usr/bin/openssl")
                self._recon_result.certificate_info = await certificate_info(self.target, runner=runner)
                self._tools_used.append("openssl")
            group1.append(self._run_subtask("certificates", do_certs()))

        if group1:
            await run_parallel(group1)

        # Group 2: Discovery tools (depend on subdomains from group 1, run in parallel)
        group2 = []

        if self._is_enabled("httpx"):
            async def do_httpx():
                cfg = self.config.tools.httpx_tool
                if not cfg.enabled:
                    return
                runner = self._make_runner("httpx", str(cfg.path))
                # Smart pipeline: probe all subdomains, not just main target
                targets = [s.name for s in self._recon_result.subdomains]
                if self.target not in targets:
                    targets.append(self.target)
                if len(targets) > 1:
                    self._recon_result.http_probes = await httpx_probe_multi(targets, runner=runner)
                else:
                    self._recon_result.http_probes = await httpx_probe(self.target, runner=runner)
                self._tools_used.append("httpx")
            group2.append(self._run_subtask("httpx", do_httpx()))

        if self._is_enabled("katana"):
            async def do_katana():
                cfg = self.config.tools.katana
                if not cfg.enabled:
                    return
                runner = self._make_runner("katana", str(cfg.path))
                self._recon_result.crawl_results = await katana_crawl(self.target, runner=runner)
                self._tools_used.append("katana")
            group2.append(self._run_subtask("katana", do_katana()))

        if self._is_enabled("gau"):
            async def do_gau():
                cfg = self.config.tools.gau
                if not cfg.enabled:
                    return
                runner = self._make_runner("gau", str(cfg.path))
                self._recon_result.historical_urls = await gau_discover(self.target, runner=runner)
                self._tools_used.append("gau")
            group2.append(self._run_subtask("gau", do_gau()))

        if self._is_enabled("dnsx"):
            async def do_dnsx():
                cfg = self.config.tools.dnsx
                if not cfg.enabled:
                    return
                targets = [s.name for s in self._recon_result.subdomains] or [self.target]
                runner = self._make_runner("dnsx", str(cfg.path))
                result = await runner.run(["-json", "-silent", "-a", "-aaaa", "-cname"])
                self._recon_result.dns_resolutions = parse_dnsx_output(result.stdout)
                self._tools_used.append("dnsx")
            group2.append(self._run_subtask("dnsx", do_dnsx()))

        if self._is_enabled("tlsx"):
            async def do_tlsx():
                cfg = self.config.tools.tlsx
                if not cfg.enabled:
                    return
                targets = [f"{self.target}:443"]
                runner = self._make_runner("tlsx", str(cfg.path))
                self._recon_result.tls_certs = await tlsx_scan(targets, runner=runner)
                self._tools_used.append("tlsx")
            group2.append(self._run_subtask("tlsx", do_tlsx()))

        if self._is_enabled("screenshots"):
            async def do_screenshots():
                urls = [p.url for p in self._recon_result.http_probes]
                if not urls:
                    urls = [f"https://{self.target}"]
                home = Path.home() / ".argus-lite" / "scans" / self._scan_id / "screenshots"
                self._recon_result.screenshots = await gowitness_capture(
                    urls, output_dir=str(home),
                )
                self._tools_used.append("gowitness")
            group2.append(self._run_subtask("screenshots", do_screenshots()))

        if group2:
            await run_parallel(group2)

    def _extract_tech_tags(self) -> list[str]:
        """Extract known technology tags for nuclei template targeting."""
        known = {"wordpress", "php", "apache", "nginx", "joomla", "drupal",
                 "iis", "tomcat", "flask", "django", "laravel", "spring"}
        tags = []
        for tech in self._analysis_result.technologies:
            name = tech.name.lower()
            if name in known:
                tags.append(name)
        return tags

    async def _run_analysis(self) -> None:
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan, ffuf_scan_with_seeds
        from argus_lite.modules.analysis.nuclei import nuclei_scan, nuclei_scan_multi
        from argus_lite.modules.analysis.ports import port_scan
        from argus_lite.modules.analysis.security_headers import (
            analyze_security_headers,
            security_headers_findings,
        )
        from argus_lite.modules.analysis.ssl import ssl_check
        from argus_lite.modules.analysis.techstack import tech_scan

        # Group A: ports, techstack, headers, ssl (independent, parallel)
        group_a = []

        if self._is_enabled("ports"):
            async def do_ports():
                cfg = self.config.tools.naabu
                if not cfg.enabled:
                    return
                runner = self._make_runner("naabu", str(cfg.path))
                self._analysis_result.open_ports = await port_scan(self.target, runner=runner)
                self._tools_used.append("naabu")
            group_a.append(self._run_subtask("ports", do_ports()))

        if self._is_enabled("techstack"):
            async def do_tech():
                cfg = self.config.tools.whatweb
                if not cfg.enabled:
                    return
                runner = self._make_runner("whatweb", str(cfg.path))
                self._analysis_result.technologies = await tech_scan(self.target, runner=runner)
                self._tools_used.append("whatweb")
            group_a.append(self._run_subtask("techstack", do_tech()))

        if self._is_enabled("ssl"):
            async def do_ssl():
                runner = self._make_runner("openssl", "/usr/bin/openssl")
                self._analysis_result.ssl_info = await ssl_check(self.target, runner=runner)
            group_a.append(self._run_subtask("ssl", do_ssl()))

        if self._is_enabled("headers"):
            async def do_headers():
                import httpx as _httpx
                try:
                    async with _httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                        resp = await client.head(f"https://{self.target}")
                        raw = f"HTTP/{resp.http_version} {resp.status_code}\n"
                        raw += "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                        self._analysis_result.security_headers = analyze_security_headers(raw)
                        new_findings = security_headers_findings(raw, asset=self.target)
                        self._findings.extend(new_findings)
                        if self._on_finding:
                            for f in new_findings:
                                self._on_finding(f)
                except Exception:
                    pass
            group_a.append(self._run_subtask("headers", do_headers()))

        if group_a:
            await run_parallel(group_a)

        # Group B: nuclei (uses tech tags from A) + ffuf (uses crawl seeds)
        group_b = []

        if self._is_enabled("nuclei"):
            async def do_nuclei():
                cfg = self.config.tools.nuclei
                if not cfg.enabled:
                    return
                runner = self._make_runner("nuclei", str(cfg.path))
                live_urls = [p.url for p in self._recon_result.http_probes if p.status_code < 400]
                tech_tags = self._extract_tech_tags()
                if len(live_urls) > 1:
                    self._analysis_result.nuclei_findings = await nuclei_scan_multi(
                        live_urls, runner=runner, tags=tech_tags or None,
                    )
                else:
                    target = live_urls[0] if live_urls else f"https://{self.target}"
                    self._analysis_result.nuclei_findings = await nuclei_scan(target, runner=runner)
                self._tools_used.append("nuclei")
            group_b.append(self._run_subtask("nuclei", do_nuclei()))

        if self._is_enabled("ffuf"):
            async def do_ffuf():
                cfg = self.config.tools.ffuf
                if not cfg.enabled:
                    return
                runner = self._make_runner("ffuf", str(cfg.path))
                seed_paths = [c.url for c in self._recon_result.crawl_results]
                from urllib.parse import urlparse
                seed_paths = [urlparse(u).path for u in seed_paths if urlparse(u).path]
                if seed_paths:
                    self._analysis_result.fuzz_results = await ffuf_scan_with_seeds(
                        f"https://{self.target}", runner=runner, seed_paths=seed_paths,
                    )
                else:
                    self._analysis_result.fuzz_results = await ffuf_scan(
                        f"https://{self.target}", runner=runner,
                    )
                self._tools_used.append("ffuf")
            group_b.append(self._run_subtask("ffuf", do_ffuf()))

        if group_b:
            await run_parallel(group_b)

    async def _run_cve_enrichment(self) -> None:
        """Query NVD API for CVEs matching detected technologies."""
        from argus_lite.core.cve_enricher import CveEnricher

        enricher = CveEnricher(api_key=self.config.api_keys.nvd_api_key)
        vulns = await enricher.enrich(self._analysis_result.technologies)
        self._vulnerabilities.extend(vulns)

    async def _run_plugins(self) -> None:
        """Execute any loaded plugins."""
        from argus_lite.core.plugin_loader import PluginLoader

        try:
            dirs = [Path(d).expanduser() for d in self.config.plugins.plugin_dirs]
            loader = PluginLoader(dirs)
            plugins = loader.load_all()

            if not plugins:
                return

            self._on_progress("plugins", "start")

            context = {
                "target": self.target,
                "recon": self._recon_result,
                "analysis": self._analysis_result,
                "findings": self._findings,
                "tools_used": self._tools_used,
            }

            for name, plugin in plugins.items():
                try:
                    if plugin.check_available():
                        await plugin.run(context, self.config)
                        self._tools_used.append(f"plugin:{name}")
                except Exception as exc:
                    logger.warning("Plugin '%s' failed: %s", name, exc)

            self._on_progress("plugins", "done")
        except Exception as exc:
            logger.debug("Plugin loading failed: %s", exc)

    def _make_runner(self, name: str, default_path: str) -> BaseToolRunner:
        return BaseToolRunner(name=name, path=default_path)
