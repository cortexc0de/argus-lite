"""Port scanning via naabu."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import Port

# Well-known port to service mapping
_KNOWN_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


def _guess_service(port: int, tls: bool) -> str:
    """Guess service name from port number."""
    if port in _KNOWN_SERVICES:
        return _KNOWN_SERVICES[port]
    if tls:
        return "https"
    return ""


def parse_naabu_output(raw: str) -> list[Port]:
    """Parse naabu JSON-lines output into Port list."""
    if not raw.strip():
        return []

    ports: list[Port] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        port_num = data.get("port", 0)
        protocol = data.get("protocol", "tcp")
        tls = data.get("tls", False)
        service = _guess_service(port_num, tls)

        ports.append(
            Port(port=port_num, protocol=protocol, service=service, banner="")
        )

    ports.sort(key=lambda p: p.port)
    return ports


async def port_scan(
    target: str,
    runner: BaseToolRunner | None = None,
    top_ports: int = 1000,
) -> list[Port]:
    """Run naabu and parse open ports."""
    if runner is None:
        runner = BaseToolRunner(name="naabu", path="/usr/bin/naabu")

    result: ToolOutput = await runner.run([
        "-host", target, "-top-ports", str(top_ports), "-json", "-silent",
    ])
    return parse_naabu_output(result.stdout)
