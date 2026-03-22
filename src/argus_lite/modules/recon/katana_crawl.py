"""Web crawling via katana."""

from __future__ import annotations

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import CrawlResult


def parse_katana_output(raw: str) -> list[CrawlResult]:
    """Parse katana text output (one URL per line) into CrawlResult list.

    Deduplicates URLs while preserving first-seen order.
    """
    if not raw.strip():
        return []

    seen: set[str] = set()
    results: list[CrawlResult] = []

    for line in raw.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(CrawlResult(url=url))

    return results


async def katana_crawl(
    target: str,
    runner: BaseToolRunner | None = None,
    depth: int = 3,
) -> list[CrawlResult]:
    """Run katana and parse crawled URLs for a target."""
    if runner is None:
        runner = BaseToolRunner(name="katana", path="/usr/bin/katana")

    result: ToolOutput = await runner.run(
        ["-u", target, "-d", str(depth), "-silent"]
    )
    return parse_katana_output(result.stdout)
