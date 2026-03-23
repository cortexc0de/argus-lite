"""HTTP probing via httpx."""

from __future__ import annotations

import json
import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import HttpProbe

_RESPONSE_TIME_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def parse_httpx_output(raw: str) -> list[HttpProbe]:
    """Parse httpx JSON-lines output into HttpProbe list.

    Skips entries where ``failed`` is true.  Extracts ``response_time_ms``
    from strings like ``"125ms"`` or ``"4.5ms"``.
    """
    if not raw.strip():
        return []

    results: list[HttpProbe] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if entry.get("failed", False):
            continue

        # Extract response_time_ms from string like "125ms"
        response_time_ms = 0
        rt_raw = entry.get("response_time", "")
        if rt_raw:
            match = _RESPONSE_TIME_RE.search(str(rt_raw))
            if match:
                response_time_ms = int(float(match.group(1)))

        results.append(
            HttpProbe(
                url=entry.get("url", ""),
                status_code=entry.get("status_code", 0),
                title=entry.get("title", ""),
                content_length=entry.get("content_length", 0),
                content_type=entry.get("content_type", ""),
                tech=entry.get("tech", []),
                server=entry.get("server", ""),
                response_time_ms=response_time_ms,
            )
        )

    return results


async def httpx_probe(
    target: str,
    runner: BaseToolRunner | None = None,
) -> list[HttpProbe]:
    """Run httpx and parse HTTP probe results for a single target."""
    if runner is None:
        runner = BaseToolRunner(name="httpx", path="/usr/bin/httpx")

    result: ToolOutput = await runner.run(
        ["-u", target, "-json", "-silent", "-title", "-tech-detect",
         "-status-code", "-content-length"]
    )
    return parse_httpx_output(result.stdout)


async def httpx_probe_multi(
    targets: list[str],
    runner: BaseToolRunner | None = None,
) -> list[HttpProbe]:
    """Run httpx against multiple targets via temp file."""
    import tempfile
    from pathlib import Path

    if runner is None:
        runner = BaseToolRunner(name="httpx", path="/usr/bin/httpx")

    if not targets:
        return []

    # Deduplicate
    unique = list(dict.fromkeys(targets))

    # Write targets to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp.write("\n".join(unique))
        tmp.close()

        result: ToolOutput = await runner.run(
            ["-l", tmp.name, "-json", "-silent", "-title", "-tech-detect",
             "-status-code", "-content-length"]
        )
        return parse_httpx_output(result.stdout)
    finally:
        Path(tmp.name).unlink(missing_ok=True)
