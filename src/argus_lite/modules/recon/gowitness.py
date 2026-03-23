"""Screenshot capture via gowitness."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import Screenshot

# gowitness needs Chrome/Chromium; give it a reasonable timeout
_GOWITNESS_TIMEOUT = 60


def parse_gowitness_output(raw: str) -> list[Screenshot]:
    """Parse gowitness JSON-lines output."""
    if not raw.strip():
        return []

    results: list[Screenshot] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        results.append(
            Screenshot(
                url=data.get("url", ""),
                final_url=data.get("final_url", ""),
                status_code=data.get("status_code", 0),
                title=data.get("title", ""),
                filename=data.get("filename", ""),
                screenshot_path=data.get("screenshot_path", ""),
                response_time_ms=data.get("response_time_ms", 0),
            )
        )

    return results


async def gowitness_capture(
    urls: list[str],
    runner: BaseToolRunner | None = None,
    output_dir: str = "/tmp/argus-screenshots",
) -> list[Screenshot]:
    """Run gowitness to capture screenshots of given URLs.

    Uses a temp file for the URL list (avoids stdin blocking).
    Timeout reduced to 60s (gowitness needs Chrome — if unavailable, fail fast).
    """
    if runner is None:
        runner = BaseToolRunner(name="gowitness", path="/usr/local/bin/gowitness")

    if not urls:
        return []

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Write URLs to a temp file — avoids /dev/stdin blocking on subprocess
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="argus-urls-") as f:
        f.write("\n".join(urls))
        url_file = f.name

    try:
        result: ToolOutput = await runner.run(
            [
                "scan", "file",
                "-f", url_file,
                "--screenshot-path", output_dir,
                "--write-jsonl",
                "--quiet",
                "--timeout", "10",
            ],
            timeout=_GOWITNESS_TIMEOUT,
        )
        return parse_gowitness_output(result.stdout)
    finally:
        try:
            Path(url_file).unlink(missing_ok=True)
        except Exception:
            pass
