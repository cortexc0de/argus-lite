"""Certificate info via openssl."""

from __future__ import annotations

import re

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.recon import CertificateInfo

_ISSUER_RE = re.compile(r"Issuer:\s*(.+)")
_SUBJECT_RE = re.compile(r"Subject:(?!.*Public Key)\s*(.+)")
_NOT_BEFORE_RE = re.compile(r"Not Before:\s*(.+)")
_NOT_AFTER_RE = re.compile(r"Not After\s*:\s*(.+)")
_SERIAL_RE = re.compile(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+)")
_SAN_RE = re.compile(r"Subject Alternative Name:\s*\n?\s*(.+)")


def parse_openssl_output(raw: str) -> CertificateInfo:
    """Parse openssl x509 text output into CertificateInfo."""
    if not raw.strip():
        return CertificateInfo()

    subject = ""
    issuer = ""
    not_before = ""
    not_after = ""
    serial_number = ""
    san: list[str] = []

    lines = raw.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()

        m = _ISSUER_RE.match(stripped)
        if m and not issuer:
            issuer = m.group(1).strip()

        m = _SUBJECT_RE.match(stripped)
        if m and not subject:
            subject = m.group(1).strip()

        m = _NOT_BEFORE_RE.match(stripped)
        if m and not not_before:
            not_before = m.group(1).strip()

        m = _NOT_AFTER_RE.match(stripped)
        if m and not not_after:
            not_after = m.group(1).strip()

        if "Serial Number:" in stripped:
            # Serial may be on the next line
            if i + 1 < len(lines):
                serial_candidate = lines[i + 1].strip()
                if re.match(r"^[0-9a-fA-F:]+$", serial_candidate):
                    serial_number = serial_candidate

        if "Subject Alternative Name:" in stripped:
            # SAN entries are on the next line(s)
            if i + 1 < len(lines):
                san_line = lines[i + 1].strip()
                san = _parse_san_line(san_line)

    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        san=san,
        serial_number=serial_number,
    )


def _parse_san_line(san_line: str) -> list[str]:
    """Parse SAN line like 'DNS:www.example.org, DNS:example.com' into list."""
    entries: list[str] = []
    for part in san_line.split(","):
        part = part.strip()
        if part.startswith("DNS:"):
            entries.append(part[4:].strip())
        elif part.startswith("IP Address:"):
            entries.append(part[11:].strip())
    return entries


async def certificate_info(
    target: str,
    runner: BaseToolRunner | None = None,
) -> CertificateInfo:
    """Get certificate info via openssl."""
    if runner is None:
        runner = BaseToolRunner(name="openssl", path="/usr/bin/openssl")

    result: ToolOutput = await runner.run([
        "s_client", "-connect", f"{target}:443",
        "-servername", target,
    ])
    return parse_openssl_output(result.stdout)
