"""TLS certificate scanning via tlsx."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import TlsCert


def parse_tlsx_output(raw: str) -> list[TlsCert]:
    """Parse tlsx JSON-lines output into TlsCert list."""
    if not raw.strip():
        return []

    results: list[TlsCert] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        results.append(
            TlsCert(
                host=entry.get("host", ""),
                subject_cn=entry.get("subject_cn", ""),
                issuer=entry.get("issuer_cn", ""),
                san=entry.get("san", []),
                not_after=entry.get("not_after", ""),
                expired=entry.get("expired", False),
                self_signed=entry.get("self_signed", False),
            )
        )

    return results


async def tlsx_scan(
    targets: list[str],
    runner: BaseToolRunner | None = None,
) -> list[TlsCert]:
    """Run tlsx and parse results."""
    if runner is None:
        runner = BaseToolRunner(name="tlsx", path="/usr/bin/tlsx")

    # Pass targets as comma-separated via -host flag
    result: ToolOutput = await runner.run([
        "-host", ",".join(targets), "-json", "-silent", "-san", "-so",
    ])
    return parse_tlsx_output(result.stdout)
