"""Finding and Vulnerability models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    """A single security finding from any module."""

    id: str
    type: str
    severity: Literal["INFO", "LOW"]
    title: str
    description: str
    asset: str
    evidence: str
    source: str
    remediation: str
    false_positive: bool = False


class Vulnerability(BaseModel):
    """A vulnerability linked to a Finding, optionally with CVE info."""

    id: str
    finding_id: str
    cve: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    exploit_available: bool = False
    references: list[str] = []
