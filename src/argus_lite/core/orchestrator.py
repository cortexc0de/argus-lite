"""Scan orchestrator — main coordinator for all scan stages."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from argus_lite.core.config import AppConfig
from argus_lite.core.tool_runner import BaseToolRunner, ToolNotFoundError
from argus_lite.models.analysis import AnalysisResult
from argus_lite.models.finding import Finding
from argus_lite.models.recon import ReconResult
from argus_lite.models.scan import ScanResult, StageError

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates scan stages: recon -> analysis -> report.

    Handles errors per-stage (non-fatal), graceful shutdown,
    and progress callbacks.
    """

    def __init__(
        self,
        target: str,
        config: AppConfig,
        on_progress: Callable[[str, str], None] | None = None,
    ) -> None:
        self.target = target
        self.config = config
        self.shutdown_requested = False
        self._on_progress = on_progress or (lambda stage, status: None)
        self._scan_id = str(uuid.uuid4())
        self._tools_used: list[str] = []
        self._errors: list[StageError] = []
        self._completed_stages: list[str] = []
        self._skipped_stages: list[str] = []
        self._recon_result = ReconResult()
        self._analysis_result = AnalysisResult()
        self._findings: list[Finding] = []

    def request_shutdown(self) -> None:
        """Request graceful shutdown (called from signal handler)."""
        self.shutdown_requested = True

    async def run(self) -> ScanResult:
        """Execute all scan stages and return aggregated result."""
        started_at = datetime.now(tz=timezone.utc)

        # Stage: Recon
        await self._execute_stage("recon", self._run_recon)

        # Stage: Analysis (skip if shutdown requested)
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

    async def _execute_stage(
        self, name: str, func: Callable[[], None]
    ) -> None:
        """Execute a stage with error handling and progress reporting."""
        self._on_progress(name, "start")
        try:
            await func()
            self._completed_stages.append(name)
            self._on_progress(name, "done")
        except Exception as e:
            self._errors.append(
                StageError(
                    stage=name,
                    error_type=type(e).__name__,
                    message=str(e),
                    timestamp=datetime.now(tz=timezone.utc),
                )
            )
            self._on_progress(name, "fail")

    async def _run_subtask(self, name: str, coro) -> None:
        """Run a sub-task within a stage, catching errors gracefully."""
        if self.shutdown_requested:
            return
        try:
            await coro
        except ToolNotFoundError:
            logger.warning("Tool not found for subtask '%s', skipping", name)
        except Exception as e:
            logger.warning("Subtask '%s' failed: %s", name, e)

    async def _run_recon(self) -> None:
        """Run recon stage — DNS, whois, subdomains, certificates."""
        from argus_lite.modules.recon.certificates import certificate_info
        from argus_lite.modules.recon.dns import dns_enumerate
        from argus_lite.modules.recon.subdomains import subdomain_enumerate
        from argus_lite.modules.recon.whois import whois_lookup

        # DNS
        async def do_dns():
            runner = self._make_runner("dig", "/usr/bin/dig")
            self._recon_result.dns_records = await dns_enumerate(self.target, runner=runner)
            self._tools_used.append("dig")

        # Whois
        async def do_whois():
            runner = self._make_runner("whois", "/usr/bin/whois")
            self._recon_result.whois_info = await whois_lookup(self.target, runner=runner)
            self._tools_used.append("whois")

        # Subdomains
        async def do_subdomains():
            tool_cfg = self.config.tools.subfinder
            if not tool_cfg.enabled:
                return
            runner = self._make_runner("subfinder", str(tool_cfg.path))
            self._recon_result.subdomains = await subdomain_enumerate(self.target, runner=runner)
            self._tools_used.append("subfinder")

        # Certificates
        async def do_certs():
            runner = self._make_runner("openssl", "/usr/bin/openssl")
            self._recon_result.certificate_info = await certificate_info(self.target, runner=runner)
            self._tools_used.append("openssl")

        await self._run_subtask("dns", do_dns())
        await self._run_subtask("whois", do_whois())
        await self._run_subtask("subdomains", do_subdomains())
        await self._run_subtask("certificates", do_certs())

    async def _run_analysis(self) -> None:
        """Run analysis stage — ports, headers, tech, SSL, nuclei."""
        from argus_lite.modules.analysis.nuclei import nuclei_scan
        from argus_lite.modules.analysis.ports import port_scan
        from argus_lite.modules.analysis.security_headers import (
            analyze_security_headers,
            security_headers_findings,
        )
        from argus_lite.modules.analysis.ssl import ssl_check
        from argus_lite.modules.analysis.techstack import tech_scan

        # Port scan
        async def do_ports():
            tool_cfg = self.config.tools.naabu
            if not tool_cfg.enabled:
                return
            runner = self._make_runner("naabu", str(tool_cfg.path))
            self._analysis_result.open_ports = await port_scan(self.target, runner=runner)
            self._tools_used.append("naabu")

        # Tech stack
        async def do_tech():
            tool_cfg = self.config.tools.whatweb
            if not tool_cfg.enabled:
                return
            runner = self._make_runner("whatweb", str(tool_cfg.path))
            self._analysis_result.technologies = await tech_scan(self.target, runner=runner)
            self._tools_used.append("whatweb")

        # SSL check
        async def do_ssl():
            runner = self._make_runner("openssl", "/usr/bin/openssl")
            self._analysis_result.ssl_info = await ssl_check(self.target, runner=runner)

        # Security headers (uses httpx, no external tool)
        async def do_headers():
            import httpx
            try:
                async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
                    resp = await client.head(f"https://{self.target}")
                    raw_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                    raw_headers = f"HTTP/{resp.http_version} {resp.status_code}\n{raw_headers}"
                    self._analysis_result.security_headers = analyze_security_headers(raw_headers)
                    self._findings.extend(security_headers_findings(raw_headers, asset=self.target))
            except Exception:
                pass

        # Nuclei
        async def do_nuclei():
            tool_cfg = self.config.tools.nuclei
            if not tool_cfg.enabled:
                return
            runner = self._make_runner("nuclei", str(tool_cfg.path))
            self._analysis_result.nuclei_findings = await nuclei_scan(self.target, runner=runner)
            self._tools_used.append("nuclei")

        await self._run_subtask("ports", do_ports())
        await self._run_subtask("techstack", do_tech())
        await self._run_subtask("ssl", do_ssl())
        await self._run_subtask("headers", do_headers())
        await self._run_subtask("nuclei", do_nuclei())

    def _make_runner(self, name: str, default_path: str) -> BaseToolRunner:
        """Create a tool runner instance."""
        return BaseToolRunner(name=name, path=default_path)
