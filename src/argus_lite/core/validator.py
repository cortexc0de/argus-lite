"""Input sanitization and scope validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Strict regex — only allowed characters for domains
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$")
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
SHELL_DANGEROUS = re.compile(r'[;|$`&><\\\'"(){}\[\]!#~]')

# Private/reserved IP ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


class InputSanitizationError(Exception):
    """Raised when target input fails sanitization."""


@dataclass
class ScopeResult:
    """Result of scope validation."""

    allowed: bool = True
    reason: str = ""
    is_local_network: bool = False
    warnings: list[str] = field(default_factory=list)


def sanitize_target(target: str) -> str:
    """Sanitize and validate a scan target. Must be called FIRST.

    Strips URL scheme/path, lowercases, validates format,
    rejects shell metacharacters.
    """
    # Strip whitespace
    target = target.strip()

    if not target:
        raise InputSanitizationError("Target is empty")

    # Strip URL scheme if present
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""
        if not target:
            raise InputSanitizationError("Could not extract hostname from URL")
    # Strip path/trailing slash (for bare domains like example.com/path)
    elif "/" in target:
        target = target.split("/")[0]

    target = target.lower().strip()

    if not target:
        raise InputSanitizationError("Target is empty after normalization")

    # Reject shell metacharacters BEFORE any other processing
    if SHELL_DANGEROUS.search(target):
        raise InputSanitizationError(
            f"Target contains forbidden characters: {target}"
        )

    # Check if it's an IP address
    if IP_REGEX.match(target):
        _validate_ip(target)
        return target

    # Validate domain format
    if not DOMAIN_REGEX.match(target):
        raise InputSanitizationError(f"Invalid target format: {target}")

    # Minimum domain length (at least 2 chars, e.g. "localhost" or "a.b")
    if len(target) < 2:
        raise InputSanitizationError(f"Target too short: {target}")

    return target


def _validate_ip(ip_str: str) -> None:
    """Validate IP address octets are in range."""
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        raise InputSanitizationError(f"Invalid IP address: {ip_str}")


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_local_domain(domain: str) -> bool:
    """Check if domain looks like a local/internal target."""
    return domain in ("localhost",) or domain.endswith(".local")


def validate_scope(
    target: str,
    *,
    allowlist_path: Path | None = None,
    denylist_path: Path | None = None,
    allowlist_only: bool = False,
) -> ScopeResult:
    """Validate target against scope rules (allowlist/denylist)."""
    result = ScopeResult()

    # Check if target is a private IP or local domain
    if IP_REGEX.match(target):
        result.is_local_network = _is_private_ip(target)
    else:
        result.is_local_network = _is_local_domain(target)

    if result.is_local_network:
        result.warnings.append(f"Target '{target}' is a local/private address")

    # Check denylist first (takes priority)
    if denylist_path and denylist_path.exists():
        denied = _load_list(denylist_path)
        if target in denied:
            result.allowed = False
            result.reason = f"Target '{target}' is in the denylist"
            return result

    # Check allowlist
    if allowlist_path and allowlist_path.exists():
        allowed = _load_list(allowlist_path)
        if allowlist_only and target not in allowed:
            result.allowed = False
            result.reason = f"Target '{target}' is not in the allowlist (strict mode)"
            return result

    return result


def _load_list(path: Path) -> set[str]:
    """Load a line-separated list of targets."""
    content = path.read_text()
    return {
        line.strip().lower()
        for line in content.splitlines()
        if line.strip() and not line.startswith("#")
    }
