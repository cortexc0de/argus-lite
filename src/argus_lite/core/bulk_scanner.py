"""BulkScanner — run ScanOrchestrator concurrently across multiple targets."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from argus_lite.core.config import AppConfig
from argus_lite.models.bulk import BulkScanResult, BulkScanSummary
from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)

_RISK_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


class BulkScanner:
    """Run ScanOrchestrator concurrently across multiple targets."""

    def __init__(
        self,
        config: AppConfig,
        preset: str = "bulk",
        concurrency: int = 5,
        on_target_start: Callable[[str], None] | None = None,
        on_target_done: Callable[[str, ScanResult], None] | None = None,
        on_target_fail: Callable[[str, str], None] | None = None,
    ) -> None:
        self._config = config
        self._preset = preset
        self._concurrency = concurrency
        self._on_target_start = on_target_start
        self._on_target_done = on_target_done
        self._on_target_fail = on_target_fail

    async def run(self, targets: list[str]) -> BulkScanResult:
        """Scan all targets with a concurrency semaphore.

        Failed targets are recorded but do not abort the overall run.
        """
        bulk_id = str(uuid.uuid4())
        started_at = datetime.now(tz=timezone.utc)

        sem = asyncio.Semaphore(self._concurrency)
        tasks = [self._scan_one(t, sem) for t in targets]
        raw_results = await asyncio.gather(*tasks, return_exceptions=False)

        completed_results: list[ScanResult] = []
        failed: list[str] = []
        for target, result in zip(targets, raw_results):
            if result is None:
                failed.append(target)
            else:
                completed_results.append(result)

        summary = self._compute_summary(completed_results, failed)
        summary.total_targets = len(targets)

        return BulkScanResult(
            bulk_id=bulk_id,
            sources=targets,
            scan_results=completed_results,
            failed_targets=failed,
            summary=summary,
            started_at=started_at,
            completed_at=datetime.now(tz=timezone.utc),
            preset=self._preset,
        )

    async def _scan_one(self, target: str, sem: asyncio.Semaphore) -> ScanResult | None:
        """Scan a single target under semaphore. Returns None on failure."""
        async with sem:
            if self._on_target_start:
                try:
                    self._on_target_start(target)
                except Exception:
                    pass

            try:
                from argus_lite.core.orchestrator import ScanOrchestrator
                from argus_lite.core.risk_scorer import score_scan

                orch = ScanOrchestrator(
                    target=target,
                    config=self._config,
                    preset=self._preset,
                )
                result = await orch.run()
                result.risk_summary = score_scan(result)

                if self._on_target_done:
                    try:
                        self._on_target_done(target, result)
                    except Exception:
                        pass

                return result

            except Exception as exc:
                logger.warning("Scan failed for target '%s': %s", target, exc)
                if self._on_target_fail:
                    try:
                        self._on_target_fail(target, str(exc))
                    except Exception:
                        pass
                return None

    def _compute_summary(
        self, results: list[ScanResult], failed: list[str]
    ) -> BulkScanSummary:
        """Aggregate findings, CVEs, risk levels, and technologies across all results."""
        total_findings = 0
        total_vulnerabilities = 0
        highest_risk = "NONE"
        live_hosts = 0
        tech_seen: dict[str, int] = {}
        cve_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for r in results:
            # Findings
            total_findings += len(r.findings)
            for f in r.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            # Vulnerabilities (CVEs)
            total_vulnerabilities += len(r.vulnerabilities)
            for v in r.vulnerabilities:
                if v.cve:
                    cve_counts[v.cve] = cve_counts.get(v.cve, 0) + 1

            # Risk level
            if r.risk_summary:
                rl = r.risk_summary.risk_level
                if _RISK_ORDER.get(rl, 0) > _RISK_ORDER.get(highest_risk, 0):
                    highest_risk = rl

            # Live hosts — consider live if httpx found any probes
            if r.recon.http_probes:
                live_hosts += 1

            # Technologies
            for t in r.analysis.technologies:
                if t.name:
                    tech_seen[t.name] = tech_seen.get(t.name, 0) + 1

        # Top CVEs = CVEs found on 2+ targets
        top_cves = [cve for cve, cnt in sorted(cve_counts.items(), key=lambda x: -x[1]) if cnt >= 2]

        return BulkScanSummary(
            total_targets=len(results) + len(failed),
            completed=len(results),
            failed=len(failed),
            live_hosts=live_hosts,
            total_findings=total_findings,
            total_vulnerabilities=total_vulnerabilities,
            highest_risk=highest_risk,
            technologies_seen=list(tech_seen.keys()),
            top_cves=top_cves,
            findings_by_severity=severity_counts,
        )
