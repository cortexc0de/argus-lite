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


async def nuclei_scan(
    target: str,
    runner: BaseToolRunner | None = None,
    templates: list[str] | None = None,
) -> list[NucleiFinding]:
    """Run nuclei and parse findings. ONLY info/low severity returned."""
    if runner is None:
        runner = BaseToolRunner(name="nuclei", path="/usr/bin/nuclei")

    args = [
        "-u", target,
        "-severity", "info,low",  # Request only info/low from nuclei
        "-jsonl",
        "-silent",
    ]
    if templates:
        for t in templates:
            args.extend(["-t", t])

    result: ToolOutput = await runner.run(args)

    # Double enforcement: parse also filters
    return parse_nuclei_output(result.stdout)
