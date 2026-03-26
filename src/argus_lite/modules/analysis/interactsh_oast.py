"""Interactsh OAST (Out-of-Band Application Security Testing) integration."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import InteractshEvent


def parse_interactsh_output(raw: str) -> list[InteractshEvent]:
    """Parse interactsh-client output for OOB interactions."""
    if not raw.strip():
        return []

    events: list[InteractshEvent] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Format: [protocol] Received XXX interaction from IP at timestamp
        match = re.match(
            r"\[(\w+)\]\s+Received\s+\w+\s+interaction\s+from\s+(\S+)\s+at\s+(.+)",
            line,
        )
        if match:
            events.append(InteractshEvent(
                protocol=match.group(1),
                remote_address=match.group(2),
                timestamp=match.group(3).strip(),
            ))

    return events


async def interactsh_listen(
    duration: int = 60,
    runner: BaseToolRunner | None = None,
) -> tuple[str, list[InteractshEvent]]:
    """Start interactsh-client, listen for interactions for `duration` seconds.

    Returns (interact_url, events).
    The interact_url should be used in payloads to trigger OOB callbacks.
    """
    if runner is None:
        runner = BaseToolRunner(name="interactsh-client", path="/usr/local/bin/interactsh-client")

    result: ToolOutput = await runner.run(
        ["-n", "1", "-poll-interval", "5", "-json"],
        timeout=duration + 10,
    )

    # Extract the interaction URL from output
    interact_url = ""
    for line in result.stdout.splitlines():
        if ".oast." in line or ".interact.sh" in line:
            # Extract URL-like string
            url_match = re.search(r"(\S+\.(?:oast|interact)\.\S+)", line)
            if url_match:
                interact_url = url_match.group(1)
                break

    events = parse_interactsh_output(result.stdout)
    return interact_url, events
