"""SQLMap SQL injection scanner integration."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import SqlmapFinding


def parse_sqlmap_output(raw: str, url: str = "") -> list[SqlmapFinding]:
    """Parse SQLMap text output for injection findings."""
    if not raw.strip():
        return []

    findings: list[SqlmapFinding] = []
    current_param = ""
    current_dbms = ""

    # Extract DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", raw)
    if dbms_match:
        current_dbms = dbms_match.group(1).strip()

    # Extract parameter
    param_match = re.search(r"Parameter:\s*(\S+)", raw)
    if param_match:
        current_param = param_match.group(1)

    # Extract injection types
    for match in re.finditer(
        r"Type:\s*(.+?)(?:\n\s+.*?)*?Payload:\s*(.+?)(?:\n|$)", raw
    ):
        inj_type = match.group(1).strip()
        payload = match.group(2).strip()

        findings.append(SqlmapFinding(
            url=url,
            param=current_param,
            type=inj_type,
            dbms=current_dbms,
            payload=payload,
        ))

    return findings


async def sqlmap_scan(
    target_url: str,
    runner: BaseToolRunner | None = None,
    level: int = 1,
    risk: int = 1,
) -> list[SqlmapFinding]:
    """Run SQLMap against a target URL.

    Level 1-5 (default 1), Risk 1-3 (default 1) — higher = more aggressive.
    """
    if runner is None:
        runner = BaseToolRunner(name="sqlmap", path="/usr/bin/sqlmap")

    result: ToolOutput = await runner.run(
        [
            "-u", target_url,
            "--batch",              # non-interactive
            "--level", str(level),
            "--risk", str(risk),
            "--threads", "4",
            "--output-dir", "/tmp/argus-sqlmap",
            "--disable-coloring",
        ],
        timeout=180,
    )

    return parse_sqlmap_output(result.stdout, url=target_url)
