"""Directory/path fuzzing via ffuf."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import FfufResult


def parse_ffuf_output(raw: str) -> list[FfufResult]:
    """Parse ffuf JSON output into FfufResult list.

    Expects a JSON object with a ``results`` array.
    """
    if not raw.strip():
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    entries = data.get("results", [])
    results: list[FfufResult] = []

    for entry in entries:
        results.append(
            FfufResult(
                url=entry.get("url", ""),
                status_code=entry.get("status", 0),
                content_length=entry.get("length", 0),
                words=entry.get("words", 0),
                lines=entry.get("lines", 0),
                redirect_location=entry.get("redirectlocation", ""),
            )
        )

    return results


async def ffuf_scan(
    target: str,
    runner: BaseToolRunner | None = None,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> list[FfufResult]:
    """Run ffuf and parse directory fuzzing results for a target."""
    if runner is None:
        runner = BaseToolRunner(name="ffuf", path="/usr/bin/ffuf")

    result: ToolOutput = await runner.run(
        ["-u", f"{target}/FUZZ", "-w", wordlist, "-o", "-", "-of", "json", "-s"]
    )
    return parse_ffuf_output(result.stdout)


async def ffuf_scan_with_seeds(
    target: str,
    runner: BaseToolRunner | None = None,
    seed_paths: list[str] | None = None,
    base_wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> list[FfufResult]:
    """Run ffuf with seed paths from crawling added to the wordlist."""
    import tempfile
    from pathlib import Path
    from urllib.parse import urlparse

    if runner is None:
        runner = BaseToolRunner(name="ffuf", path="/usr/bin/ffuf")

    wordlist = base_wordlist

    if seed_paths:
        # Extract unique path segments from crawled URLs
        seeds: set[str] = set()
        for p in seed_paths:
            cleaned = p.strip("/")
            if cleaned:
                seeds.add(cleaned)
                # Also add parent dirs
                parts = cleaned.split("/")
                for i in range(len(parts)):
                    segment = "/".join(parts[: i + 1])
                    if segment:
                        seeds.add(segment)

        if seeds:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            try:
                # Read base wordlist if it exists
                base = Path(base_wordlist)
                if base.exists():
                    tmp.write(base.read_text())
                    if not tmp.name.endswith("\n"):
                        tmp.write("\n")
                # Append seeds
                tmp.write("\n".join(sorted(seeds)))
                tmp.close()
                wordlist = tmp.name
            except Exception:
                wordlist = base_wordlist

    result: ToolOutput = await runner.run(
        ["-u", f"{target}/FUZZ", "-w", wordlist, "-o", "-", "-of", "json", "-s"]
    )
    return parse_ffuf_output(result.stdout)
