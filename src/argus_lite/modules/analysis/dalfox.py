"""Dalfox XSS scanner integration."""

from __future__ import annotations

import json
import tempfile

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import DalfoxFinding


def parse_dalfox_output(raw: str) -> list[DalfoxFinding]:
    """Parse Dalfox JSON output."""
    if not raw.strip():
        return []

    findings: list[DalfoxFinding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        xss_type = {"R": "reflected", "S": "stored", "V": "dom"}.get(
            data.get("type", ""), data.get("type", "")
        )
        findings.append(DalfoxFinding(
            url=data.get("data", ""),
            param=data.get("param", ""),
            payload=data.get("payload", ""),
            type=xss_type,
            evidence=data.get("evidence", ""),
        ))

    return findings


async def dalfox_scan(
    target: str,
    runner: BaseToolRunner | None = None,
    urls: list[str] | None = None,
) -> list[DalfoxFinding]:
    """Run Dalfox XSS scanner.

    Can scan a single URL or a list of URLs (from crawler/gf output).
    """
    if runner is None:
        runner = BaseToolRunner(name="dalfox", path="/usr/local/bin/dalfox")

    if urls:
        # Pipe mode: scan multiple URLs from file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="argus-dalfox-") as f:
            f.write("\n".join(urls))
            url_file = f.name

        result: ToolOutput = await runner.run(
            ["pipe", "-f", url_file, "--silence", "--format", "json", "--no-color"],
            timeout=120,
        )
    else:
        result = await runner.run(
            ["url", target, "--silence", "--format", "json", "--no-color"],
            timeout=120,
        )

    return parse_dalfox_output(result.stdout)
