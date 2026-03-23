"""Nuclei integration with severity ceiling enforcement."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import NucleiFinding

# HARD CEILING — enforced in code, NOT just config
ALLOWED_SEVERITIES = frozenset({"info", "low"})


def parse_nuclei_output(raw: str) -> list[NucleiFinding]:
    """Parse nuclei JSON-lines output, filtering out forbidden severities.

    SECURITY: medium/high/critical findings are SILENTLY DROPPED.
    This is the enforcement layer — even if nuclei returns them, we don't use them.
    """
    if not raw.strip():
        return []

    findings: list[NucleiFinding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        severity = info.get("severity", "unknown").lower()

        # ENFORCE SEVERITY CEILING
        if severity not in ALLOWED_SEVERITIES:
            continue

        findings.append(
            NucleiFinding(
                template_id=data.get("template-id", ""),
                name=info.get("name", ""),
                severity=severity,
                matched_at=data.get("matched-at", ""),
                description=info.get("description", ""),
                reference=info.get("reference", []) or [],
                tags=info.get("tags", []) or [],
            )
        )

    return findings


def build_nuclei_args(
    target: str,
    templates: list[str] | None = None,
) -> list[str]:
    """Build nuclei CLI arguments. Severity is ALWAYS info,low."""
    args = [
        "-u", target,
        "-severity", "info,low",
        "-jsonl",
        "-silent",
    ]
    if templates:
        for t in templates:
            args.extend(["-t", t])
    return args


async def nuclei_scan(
    target: str,
    runner: BaseToolRunner | None = None,
    templates: list[str] | None = None,
) -> list[NucleiFinding]:
    """Run nuclei and parse findings. ONLY info/low severity returned."""
    if runner is None:
        runner = BaseToolRunner(name="nuclei", path="/usr/bin/nuclei")

    args = build_nuclei_args(target, templates)
    result: ToolOutput = await runner.run(args)

    # Double enforcement: parse also filters
    return parse_nuclei_output(result.stdout)


def build_nuclei_args_multi(
    targets_file: str,
    templates: list[str] | None = None,
    tags: list[str] | None = None,
) -> list[str]:
    """Build nuclei args for multi-target scan."""
    args = [
        "-l", targets_file,
        "-severity", "info,low",
        "-jsonl",
        "-silent",
    ]
    if templates:
        for t in templates:
            args.extend(["-t", t])
    if tags:
        args.extend(["-tags", ",".join(tags)])
    return args


async def nuclei_scan_multi(
    targets: list[str],
    runner: BaseToolRunner | None = None,
    templates: list[str] | None = None,
    tags: list[str] | None = None,
) -> list[NucleiFinding]:
    """Run nuclei against multiple targets. ONLY info/low severity returned."""
    import tempfile
    from pathlib import Path

    if runner is None:
        runner = BaseToolRunner(name="nuclei", path="/usr/bin/nuclei")

    if not targets:
        return []

    unique = list(dict.fromkeys(targets))
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp.write("\n".join(unique))
        tmp.close()

        args = build_nuclei_args_multi(tmp.name, templates, tags)
        result: ToolOutput = await runner.run(args)
        return parse_nuclei_output(result.stdout)
    finally:
        Path(tmp.name).unlink(missing_ok=True)
