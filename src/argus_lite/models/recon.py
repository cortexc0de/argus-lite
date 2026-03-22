"""Recon module result models."""

from __future__ import annotations

from pydantic import BaseModel


class DNSRecord(BaseModel):
    type: str  # A, AAAA, MX, NS, TXT, CNAME
    name: str
    value: str
    ttl: int


class Subdomain(BaseModel):
    name: str
    source: str = ""  # crt.sh, subfinder, etc.
    resolved_ips: list[str] = []


class WhoisInfo(BaseModel):
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: list[str] = []
    raw: str = ""


class CertificateInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = []
    serial_number: str = ""


class ReconResult(BaseModel):
    """Aggregated result from recon module."""

    dns_records: list[DNSRecord] = []
    subdomains: list[Subdomain] = []
    whois_info: WhoisInfo | None = None
    certificate_info: CertificateInfo | None = None
