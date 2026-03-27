"""Finding and Vulnerability models."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from argus_lite.models.analysis import NucleiFinding

VALID_SEVERITIES: frozenset[str] = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})

SENSITIVE_PATHS: tuple[str, ...] = (
    "/admin", "/backup", "/.git", "/.env", "/wp-admin", "/phpmyadmin",
    "/config", "/debug", "/api/", "/.htaccess",
)


def normalize_severity(raw: str) -> str:
    """Normalize a severity string to a valid Finding severity level."""
    sev = raw.upper() if raw else "INFO"
    return sev if sev in VALID_SEVERITIES else "INFO"


class Finding(BaseModel):
    """A single security finding from any module."""

    id: str
    type: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str
    description: str
    asset: str
    evidence: str
    source: str
    remediation: str
    false_positive: bool = False


def nuclei_finding_to_finding(nf: "NucleiFinding", target: str) -> Finding:
    """Convert a NucleiFinding to a Finding object."""
    return Finding(
        id=f"nuclei-{nf.template_id}",
        type="nuclei",
        severity=normalize_severity(nf.severity),
        title=nf.name or nf.template_id,
        description=nf.description or f"Nuclei template {nf.template_id} matched",
        asset=nf.matched_at or target,
        evidence=f"Template: {nf.template_id}" + (f", tags: {', '.join(nf.tags)}" if nf.tags else ""),
        source="nuclei",
        remediation="Review and fix the identified issue",
    )


class Vulnerability(BaseModel):
    """A vulnerability linked to a Finding, optionally with CVE info."""

    id: str
    finding_id: str
    cve: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    exploit_available: bool = False
    references: list[str] = Field(default_factory=list)
