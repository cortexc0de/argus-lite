"""Subdomain enumeration via subfinder."""

from __future__ import annotations

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import Subdomain


def parse_subfinder_output(
    raw: str, source: str = "subfinder"
) -> list[Subdomain]:
    """Parse subfinder line-based output into Subdomain list."""
    if not raw.strip():
        return []

    seen: set[str] = set()
    results: list[Subdomain] = []

    for line in raw.splitlines():
        name = line.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        results.append(Subdomain(name=name, source=source))

    return results


async def subdomain_enumerate(
    target: str,
    runner: BaseToolRunner | None = None,
) -> list[Subdomain]:
    """Run subfinder and parse subdomains."""
    if runner is None:
        runner = BaseToolRunner(name="subfinder", path="/usr/bin/subfinder")

    result: ToolOutput = await runner.run(["-d", target, "-silent"])
    return parse_subfinder_output(result.stdout, source="subfinder")
