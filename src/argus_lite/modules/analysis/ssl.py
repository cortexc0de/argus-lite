"""SSL/TLS check via openssl s_client."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import SSLInfo

_CIPHER_RE = re.compile(r"Cipher is (\S+)")
_PROTOCOL_RE = re.compile(r"(TLSv[\d.]+|SSLv[\d.]+)")
_SUBJECT_RE = re.compile(r"^\s*\d*\s*s:(.+)")
_ISSUER_RE = re.compile(r"^\s*i:(.+)")
_VALIDITY_RE = re.compile(r"v:NotBefore:\s*(.+?);\s*NotAfter:\s*(.+)")

# Weak ciphers/protocols
_WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


def parse_ssl_output(raw: str) -> SSLInfo:
    """Parse openssl s_client output into SSLInfo."""
    if not raw.strip():
        return SSLInfo()

    protocol = ""
    cipher = ""
    subject = ""
    issuer = ""
    not_before = ""
    not_after = ""

    for line in raw.splitlines():
        stripped = line.strip()

        # Protocol and cipher: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
        m = _CIPHER_RE.search(stripped)
        if m:
            cipher = m.group(1)
        m = _PROTOCOL_RE.search(stripped)
        if m and not protocol:
            protocol = m.group(1)

        # Certificate chain subject/issuer
        m = _SUBJECT_RE.match(stripped)
        if m and not subject:
            subject = m.group(1).strip()

        m = _ISSUER_RE.match(stripped)
        if m and not issuer:
            issuer = m.group(1).strip()

        # Validity from certificate chain
        m = _VALIDITY_RE.search(stripped)
        if m:
            not_before = m.group(1).strip()
            not_after = m.group(2).strip()

    # Determine if cipher is weak
    weak_cipher = any(weak in cipher.upper() for weak in _WEAK_CIPHERS)

    # Determine if protocol is weak
    if protocol in _WEAK_PROTOCOLS:
        weak_cipher = True

    # Determine if expired
    expired = _check_expired(not_after)

    return SSLInfo(
        protocol=protocol,
        cipher=cipher,
        not_before=not_before,
        not_after=not_after,
        issuer=issuer,
        subject=subject,
        expired=expired,
        weak_cipher=weak_cipher,
    )


def _check_expired(not_after: str) -> bool:
    """Check if certificate expiry date is in the past."""
    if not not_after:
        return False
    try:
        # Try common openssl date format: "Feb 13 23:59:59 2027 GMT"
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        return dt.replace(tzinfo=timezone.utc) < datetime.now(tz=timezone.utc)
    except ValueError:
        return False


async def ssl_check(
    target: str,
    runner: BaseToolRunner | None = None,
) -> SSLInfo:
    """Run openssl s_client and parse SSL info."""
    if runner is None:
        runner = BaseToolRunner(name="openssl", path="/usr/bin/openssl")

    result: ToolOutput = await runner.run([
        "s_client", "-connect", f"{target}:443",
        "-servername", target, "-brief",
    ])
    return parse_ssl_output(result.stdout)
