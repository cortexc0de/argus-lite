"""DNS enumeration via dig."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import DNSRecord

# Record types we care about (skip SOA, OPT, etc.)
_WANTED_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SRV", "PTR"}

# Regex for dig ANSWER SECTION lines:
# example.com.  300  IN  A  93.184.216.34
_RECORD_RE = re.compile(
    r"^(\S+)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+)$"
)


def parse_dig_output(raw: str) -> list[DNSRecord]:
    """Parse dig output into structured DNS records."""
    if not raw.strip():
        return []

    records: list[DNSRecord] = []
    in_answer = False

    for line in raw.splitlines():
        line = line.strip()

        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue

        if in_answer and (line.startswith(";;") or line == ""):
            in_answer = False
            continue

        if not in_answer:
            continue

        match = _RECORD_RE.match(line)
        if not match:
            continue

        name_raw, ttl_str, rtype, value_raw = match.groups()

        if rtype not in _WANTED_TYPES:
            continue

        # Clean up values
        name = name_raw.rstrip(".")
        value = value_raw.strip().rstrip(".")

        # For TXT records, remove surrounding quotes
        if rtype == "TXT":
            value = value.strip('"')

        # For MX records, include priority in value
        # "10 mail.example.com" -> "10 mail.example.com"
        if rtype == "MX" and value.endswith("."):
            value = value.rstrip(".")

        records.append(
            DNSRecord(
                type=rtype,
                name=name,
                value=value,
                ttl=int(ttl_str),
            )
        )

    return records


async def dns_enumerate(
    target: str,
    runner: BaseToolRunner | None = None,
) -> list[DNSRecord]:
    """Run dig and parse DNS records for a target."""
    if runner is None:
        runner = BaseToolRunner(name="dig", path="/usr/bin/dig")

    result: ToolOutput = await runner.run([target, "ANY", "+noall", "+answer"])
    return parse_dig_output(result.stdout)
