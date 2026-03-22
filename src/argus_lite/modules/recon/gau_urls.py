"""Historical URL discovery via gau."""

from __future__ import annotations

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import HistoricalUrl


def parse_gau_output(
    raw: str, source: str = "gau"
) -> list[HistoricalUrl]:
    """Parse gau text output (one URL per line) into HistoricalUrl list.

    Deduplicates URLs while preserving first-seen order.
    """
    if not raw.strip():
        return []

    seen: set[str] = set()
    results: list[HistoricalUrl] = []

    for line in raw.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(HistoricalUrl(url=url, source=source))

    return results


async def gau_discover(
    target: str,
    runner: BaseToolRunner | None = None,
) -> list[HistoricalUrl]:
    """Run gau and parse historical URLs for a target."""
    if runner is None:
        runner = BaseToolRunner(name="gau", path="/usr/bin/gau")

    result: ToolOutput = await runner.run(["--subs", target])
    return parse_gau_output(result.stdout, source="gau")
