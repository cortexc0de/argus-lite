"""GF-pattern URL filtering — identifies URLs with potentially vulnerable parameters."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

# Parameter name patterns that indicate potential vulnerabilities
_PATTERNS: dict[str, list[str]] = {
    "xss": [
        "q", "s", "search", "query", "keyword", "term", "text", "input",
        "name", "title", "body", "content", "comment", "message", "value",
        "url", "redirect", "return", "next", "callback", "redir", "goto",
        "file", "path", "page", "ref", "data",
    ],
    "sqli": [
        "id", "uid", "pid", "cid", "nid", "cat", "catid", "item",
        "num", "number", "count", "order", "sort", "column", "field",
        "table", "from", "to", "date", "year", "month", "day",
        "user", "username", "login", "email", "pass", "password",
        "select", "report", "role", "update", "key", "token",
    ],
    "ssrf": [
        "url", "uri", "path", "dest", "redirect", "redir", "return",
        "next", "target", "rurl", "link", "src", "source", "image",
        "img", "load", "fetch", "proxy", "request", "callback",
    ],
    "lfi": [
        "file", "path", "folder", "dir", "include", "page", "template",
        "doc", "document", "root", "pg", "style", "view", "content",
        "layout", "read", "download", "cat", "action", "board",
    ],
}


def filter_urls_by_pattern(urls: list[str], pattern: str) -> list[str]:
    """Filter URLs that have parameters matching the given pattern.

    Patterns: "xss", "sqli", "ssrf", "lfi"
    If pattern is unknown, returns all URLs with query params.
    """
    target_params = _PATTERNS.get(pattern.lower())

    if target_params is None:
        # Unknown pattern — return all URLs that have query parameters
        return [u for u in urls if "?" in u]

    target_set = set(target_params)
    matched: list[str] = []

    for url in urls:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if any(p.lower() in target_set for p in params):
                matched.append(url)
        except Exception:
            continue

    return matched


def classify_url(url: str) -> list[str]:
    """Classify a URL by which vulnerability patterns its parameters match.

    Returns list of matching patterns, e.g. ["xss", "sqli"].
    """
    matches = []
    for pattern_name in _PATTERNS:
        if filter_urls_by_pattern([url], pattern_name):
            matches.append(pattern_name)
    return matches
