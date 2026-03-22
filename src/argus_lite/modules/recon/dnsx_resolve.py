"""DNS resolution via dnsx."""

from __future__ import annotations

import asyncio
import json
import time
from collections import Counter

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import DnsResolution

_WILDCARD_THRESHOLD = 10


def parse_dnsx_output(raw: str) -> list[DnsResolution]:
    """Parse dnsx JSON-lines output into DnsResolution list.

    Skips entries with NXDOMAIN status.  Detects wildcard DNS when more
    than ``_WILDCARD_THRESHOLD`` hosts resolve to the same IP address.
    """
    if not raw.strip():
        return []

    results: list[DnsResolution] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        status = entry.get("status_code", "")
        if status == "NXDOMAIN":
            continue

        results.append(
            DnsResolution(
                host=entry.get("host", ""),
                a=entry.get("a", []),
                aaaa=entry.get("aaaa", []),
                cname=entry.get("cname", []),
            )
        )

    # Wildcard detection: if >10 hosts resolve to the same A record,
    # mark them all as wildcard.
    ip_counter: Counter[str] = Counter()
    for res in results:
        for ip in res.a:
            ip_counter[ip] += 1

    wildcard_ips = {ip for ip, count in ip_counter.items()
                    if count > _WILDCARD_THRESHOLD}

    if wildcard_ips:
        for res in results:
            if any(ip in wildcard_ips for ip in res.a):
                res.wildcard = True

    return results


async def dnsx_resolve(
    targets: list[str],
    runner: BaseToolRunner | None = None,
) -> list[DnsResolution]:
    """Run dnsx with a list of hosts via stdin and parse results."""
    if runner is None:
        runner = BaseToolRunner(name="dnsx", path="/usr/bin/dnsx")

    if not runner.check_available():
        from argus_lite.core.tool_runner import ToolNotFoundError
        raise ToolNotFoundError(
            f"Tool '{runner.name}' not found at {runner.path} or in PATH"
        )

    stdin_data = "\n".join(targets).encode()
    command = [runner._get_executable(), "-json", "-silent", "-a", "-aaaa", "-cname"]
    start = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await asyncio.wait_for(
        proc.communicate(input=stdin_data), timeout=300
    )
    elapsed = time.monotonic() - start

    result = ToolOutput(
        returncode=proc.returncode or 0,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_seconds=round(elapsed, 3),
        command=command,
    )
    return parse_dnsx_output(result.stdout)
