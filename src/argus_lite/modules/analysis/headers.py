"""HTTP header parsing from curl output."""

from __future__ import annotations

import re


def parse_curl_headers(raw: str) -> dict[str, str | int]:
    """Parse curl -I style header output into a dict.

    Special key '_status_code' holds the HTTP status code.
    All header names are lowercased.
    """
    if not raw.strip():
        return {}

    headers: dict[str, str | int] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Status line: "HTTP/2 200" or "HTTP/1.1 200 OK"
        status_match = re.match(r"^HTTP/[\d.]+ (\d+)", line)
        if status_match:
            headers["_status_code"] = int(status_match.group(1))
            continue

        # Header: "key: value"
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    return headers
