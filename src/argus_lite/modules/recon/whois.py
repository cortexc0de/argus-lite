"""Whois lookup and parsing."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import WhoisInfo

# Common whois field patterns (case-insensitive)
_PATTERNS = {
    "domain": re.compile(r"Domain Name:\s*(.+)", re.IGNORECASE),
    "registrar": re.compile(r"Registrar:\s*(.+)", re.IGNORECASE),
    "creation_date": re.compile(r"Creation Date:\s*(.+)", re.IGNORECASE),
    "expiration_date": re.compile(r"(?:Registry Expiry Date|Expiration Date):\s*(.+)", re.IGNORECASE),
    "name_server": re.compile(r"Name Server:\s*(.+)", re.IGNORECASE),
}


def parse_whois_output(raw: str) -> WhoisInfo:
    """Parse whois output into structured WhoisInfo."""
    if not raw.strip():
        return WhoisInfo()

    domain = ""
    registrar = ""
    creation_date = ""
    expiration_date = ""
    name_servers: list[str] = []

    for line in raw.splitlines():
        line = line.strip()

        m = _PATTERNS["domain"].match(line)
        if m and not domain:
            domain = m.group(1).strip().lower()

        m = _PATTERNS["registrar"].match(line)
        if m and not registrar:
            registrar = m.group(1).strip()

        m = _PATTERNS["creation_date"].match(line)
        if m and not creation_date:
            creation_date = m.group(1).strip()

        m = _PATTERNS["expiration_date"].match(line)
        if m and not expiration_date:
            expiration_date = m.group(1).strip()

        m = _PATTERNS["name_server"].match(line)
        if m:
            ns = m.group(1).strip()
            if ns not in name_servers:
                name_servers.append(ns)

    return WhoisInfo(
        domain=domain,
        registrar=registrar,
        creation_date=creation_date,
        expiration_date=expiration_date,
        name_servers=name_servers,
        raw=raw,
    )


async def whois_lookup(
    target: str,
    runner: BaseToolRunner | None = None,
) -> WhoisInfo:
    """Run whois and parse result."""
    if runner is None:
        runner = BaseToolRunner(name="whois", path="/usr/bin/whois")

    result: ToolOutput = await runner.run([target])
    return parse_whois_output(result.stdout)
