"""Vulnerability discovery models — find hosts by CVE, tech, service."""

from __future__ import annotations

from pydantic import BaseModel


class DiscoverQuery(BaseModel):
    """What to search for across OSINT platforms."""

    cve: str = ""              # CVE-2024-1234
    tech: str = ""             # WordPress 6.3
    service: str = ""          # apache 2.4
    port: int | None = None    # 3389, 445, etc.
    country: str = ""          # RU, US, DE — ISO 3166-1 alpha-2


class DiscoverHost(BaseModel):
    """A single host found by the discovery engine."""

    ip: str
    port: int = 0
    service: str = ""
    product: str = ""
    version: str = ""
    country: str = ""
    org: str = ""
    source: str = ""           # shodan, censys, zoomeye, fofa


class DiscoverResult(BaseModel):
    """Aggregated results from all OSINT sources."""

    query: DiscoverQuery
    hosts: list[DiscoverHost] = []
    total_found: int = 0
    sources_queried: list[str] = []
    sources_failed: list[str] = []
