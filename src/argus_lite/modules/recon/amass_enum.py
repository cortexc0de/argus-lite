"""Amass subdomain enumeration — passive mode."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner
from argus_lite.models.recon import Subdomain

_VALID_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def parse_amass_output(raw: str, target: str) -> list[Subdomain]:
    """Parse amass plain-text output into Subdomain objects."""
    seen: set[str] = set()
    subs: list[Subdomain] = []
    for line in raw.strip().splitlines():
        name = line.strip().lower()
        if name and _VALID_DOMAIN.match(name) and name not in seen:
            seen.add(name)
            subs.append(Subdomain(name=name, source="amass"))
    return subs


async def amass_enumerate(target: str, runner: BaseToolRunner) -> list[Subdomain]:
    """Run amass in passive mode and return discovered subdomains."""
    result = await runner.run(["enum", "-passive", "-d", target, "-timeout", "5"])
    return parse_amass_output(result.stdout, target)
