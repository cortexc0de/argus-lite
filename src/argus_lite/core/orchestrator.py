"""Scan orchestrator — main coordinator for all scan stages."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

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
        "recon": ["dns", "whois", "subdomains", "certificates", "httpx", "katana", "gau", "dnsx", "tlsx"],
        "analysis": ["ports", "techstack", "headers", "ssl", "nuclei", "ffuf"],
    },
    "recon": {
        "recon": ["dns", "whois", "subdomains", "certificates", "dnsx", "tlsx", "gau"],
        "analysis": [],
    },
    "web": {
        "recon": ["dns", "certificates", "httpx", "katana"],
        "analysis": ["headers", "ssl", "techstack", "nuclei"],
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
    ) -> None:
        self.target = target
        self.config = config
        self.shutdown_requested = False
        self._on_progress = on_progress or (lambda stage, status: None)
        self._scan_id = str(uuid.uuid4())
        self._preset = preset
        self._tools_used: list[str] = []
        self._errors: list[StageError] = []
        self._completed_stages: list[str] = []
        self._skipped_stages: list[str] = []
        self._recon_result = ReconResult()
        self._analysis_result = AnalysisResult()
        self._findings: list[Finding] = []

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
        except ToolNotFoundError:
            logger.warning("Tool not found for subtask '%s', skipping", name)
        except Exception as e:
            logger.warning("Subtask '%s' failed: %s", name, e)

    async def _run_recon(self) -> None:
        from argus_lite.modules.recon.certificates import certificate_info
        from argus_lite.modules.recon.dns import dns_enumerate
        from argus_lite.modules.recon.dnsx_resolve import parse_dnsx_output
        from argus_lite.modules.recon.gau_urls import gau_discover
        from argus_lite.modules.recon.httpx_probe import httpx_probe
        from argus_lite.modules.recon.katana_crawl import katana_crawl
        from argus_lite.modules.recon.subdomains import subdomain_enumerate
        from argus_lite.modules.recon.tlsx_certs import tlsx_scan
        from argus_lite.modules.recon.whois import whois_lookup

        if self._is_enabled("dns"):
            async def do_dns():
                runner = self._make_runner("dig", "/usr/bin/dig")
                self._recon_result.dns_records = await dns_enumerate(self.target, runner=runner)
                self._tools_used.append("dig")
            await self._run_subtask("dns", do_dns())

        if self._is_enabled("whois"):
            async def do_whois():
                runner = self._make_runner("whois", "/usr/bin/whois")
                self._recon_result.whois_info = await whois_lookup(self.target, runner=runner)
                self._tools_used.append("whois")
            await self._run_subtask("whois", do_whois())

        if self._is_enabled("subdomains"):
            async def do_subdomains():
                cfg = self.config.tools.subfinder
                if not cfg.enabled:
                    return
                runner = self._make_runner("subfinder", str(cfg.path))
                self._recon_result.subdomains = await subdomain_enumerate(self.target, runner=runner)
                self._tools_used.append("subfinder")
            await self._run_subtask("subdomains", do_subdomains())

        if self._is_enabled("certificates"):
            async def do_certs():
                runner = self._make_runner("openssl", "/usr/bin/openssl")
                self._recon_result.certificate_info = await certificate_info(self.target, runner=runner)
                self._tools_used.append("openssl")
            await self._run_subtask("certificates", do_certs())

        if self._is_enabled("httpx"):
            async def do_httpx():
                cfg = self.config.tools.httpx_tool
                if not cfg.enabled:
                    return
                runner = self._make_runner("httpx", str(cfg.path))
                self._recon_result.http_probes = await httpx_probe(self.target, runner=runner)
                self._tools_used.append("httpx")
            await self._run_subtask("httpx", do_httpx())

        if self._is_enabled("katana"):
            async def do_katana():
                cfg = self.config.tools.katana
                if not cfg.enabled:
                    return
                runner = self._make_runner("katana", str(cfg.path))
                self._recon_result.crawl_results = await katana_crawl(self.target, runner=runner)
                self._tools_used.append("katana")
            await self._run_subtask("katana", do_katana())

        if self._is_enabled("gau"):
            async def do_gau():
                cfg = self.config.tools.gau
                if not cfg.enabled:
                    return
                runner = self._make_runner("gau", str(cfg.path))
                self._recon_result.historical_urls = await gau_discover(self.target, runner=runner)
                self._tools_used.append("gau")
            await self._run_subtask("gau", do_gau())

        if self._is_enabled("dnsx"):
            async def do_dnsx():
                cfg = self.config.tools.dnsx
                if not cfg.enabled:
                    return
                # Resolve subdomains found so far
                targets = [s.name for s in self._recon_result.subdomains] or [self.target]
                runner = self._make_runner("dnsx", str(cfg.path))
                # dnsx uses stdin, so call runner.run with special handling
                result = await runner.run(["-json", "-silent", "-a", "-aaaa", "-cname"])
                self._recon_result.dns_resolutions = parse_dnsx_output(result.stdout)
                self._tools_used.append("dnsx")
            await self._run_subtask("dnsx", do_dnsx())

        if self._is_enabled("tlsx"):
            async def do_tlsx():
                cfg = self.config.tools.tlsx
                if not cfg.enabled:
                    return
                targets = [f"{self.target}:443"]
                runner = self._make_runner("tlsx", str(cfg.path))
                self._recon_result.tls_certs = await tlsx_scan(targets, runner=runner)
                self._tools_used.append("tlsx")
            await self._run_subtask("tlsx", do_tlsx())

    async def _run_analysis(self) -> None:
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan
        from argus_lite.modules.analysis.nuclei import nuclei_scan
        from argus_lite.modules.analysis.ports import port_scan
        from argus_lite.modules.analysis.security_headers import (
            analyze_security_headers,
            security_headers_findings,
        )
        from argus_lite.modules.analysis.ssl import ssl_check
        from argus_lite.modules.analysis.techstack import tech_scan

        if self._is_enabled("ports"):
            async def do_ports():
                cfg = self.config.tools.naabu
                if not cfg.enabled:
                    return
                runner = self._make_runner("naabu", str(cfg.path))
                self._analysis_result.open_ports = await port_scan(self.target, runner=runner)
                self._tools_used.append("naabu")
            await self._run_subtask("ports", do_ports())

        if self._is_enabled("techstack"):
            async def do_tech():
                cfg = self.config.tools.whatweb
                if not cfg.enabled:
                    return
                runner = self._make_runner("whatweb", str(cfg.path))
                self._analysis_result.technologies = await tech_scan(self.target, runner=runner)
                self._tools_used.append("whatweb")
            await self._run_subtask("techstack", do_tech())

        if self._is_enabled("ssl"):
            async def do_ssl():
                runner = self._make_runner("openssl", "/usr/bin/openssl")
                self._analysis_result.ssl_info = await ssl_check(self.target, runner=runner)
            await self._run_subtask("ssl", do_ssl())

        if self._is_enabled("headers"):
            async def do_headers():
                import httpx
                try:
                    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                        resp = await client.head(f"https://{self.target}")
                        raw = f"HTTP/{resp.http_version} {resp.status_code}\n"
                        raw += "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                        self._analysis_result.security_headers = analyze_security_headers(raw)
                        self._findings.extend(security_headers_findings(raw, asset=self.target))
                except Exception:
                    pass
            await self._run_subtask("headers", do_headers())

        if self._is_enabled("nuclei"):
            async def do_nuclei():
                cfg = self.config.tools.nuclei
                if not cfg.enabled:
                    return
                runner = self._make_runner("nuclei", str(cfg.path))
                self._analysis_result.nuclei_findings = await nuclei_scan(self.target, runner=runner)
                self._tools_used.append("nuclei")
            await self._run_subtask("nuclei", do_nuclei())

        if self._is_enabled("ffuf"):
            async def do_ffuf():
                cfg = self.config.tools.ffuf
                if not cfg.enabled:
                    return
                runner = self._make_runner("ffuf", str(cfg.path))
                self._analysis_result.fuzz_results = await ffuf_scan(
                    f"https://{self.target}", runner=runner,
                )
                self._tools_used.append("ffuf")
            await self._run_subtask("ffuf", do_ffuf())

    def _make_runner(self, name: str, default_path: str) -> BaseToolRunner:
        return BaseToolRunner(name=name, path=default_path)
