"""Screenshot capture via gowitness."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import Screenshot


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
    """Run gowitness to capture screenshots of given URLs."""
    if runner is None:
        runner = BaseToolRunner(name="gowitness", path="/usr/local/bin/gowitness")

    # Write URLs to stdin via file approach
    url_list = "\n".join(urls)

    result: ToolOutput = await runner.run([
        "scan", "file", "-f", "/dev/stdin",
        "--screenshot-path", output_dir,
        "--write-jsonl",
        "--quiet",
    ])
    return parse_gowitness_output(result.stdout)
