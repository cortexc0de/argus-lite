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


class HttpProbe(BaseModel):
    url: str
    status_code: int
    title: str = ""
    content_length: int = 0
    tech: list[str] = []
    response_time_ms: int = 0
    content_type: str = ""
    server: str = ""


class CrawlResult(BaseModel):
    url: str
    method: str = "GET"
    source: str = ""
    tag: str = ""
    attribute: str = ""


class HistoricalUrl(BaseModel):
    url: str
    source: str = ""  # wayback, commoncrawl, etc.


class DnsResolution(BaseModel):
    host: str
    a: list[str] = []
    aaaa: list[str] = []
    cname: list[str] = []
    wildcard: bool = False


class TlsCert(BaseModel):
    host: str
    subject_cn: str = ""
    issuer: str = ""
    san: list[str] = []
    not_after: str = ""
    expired: bool = False
    self_signed: bool = False


class ReconResult(BaseModel):
    """Aggregated result from recon module."""

    dns_records: list[DNSRecord] = []
    subdomains: list[Subdomain] = []
    whois_info: WhoisInfo | None = None
    certificate_info: CertificateInfo | None = None
    http_probes: list[HttpProbe] = []
    crawl_results: list[CrawlResult] = []
    historical_urls: list[HistoricalUrl] = []
    dns_resolutions: list[DnsResolution] = []
    tls_certs: list[TlsCert] = []
