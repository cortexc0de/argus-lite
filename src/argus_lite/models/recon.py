"""Recon module result models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DNSRecord(BaseModel):
    type: str  # A, AAAA, MX, NS, TXT, CNAME
    name: str
    value: str
    ttl: int


class Subdomain(BaseModel):
    name: str
    source: str = ""  # crt.sh, subfinder, etc.
    resolved_ips: list[str] = Field(default_factory=list)


class WhoisInfo(BaseModel):
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: list[str] = Field(default_factory=list)
    raw: str = ""


class CertificateInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = Field(default_factory=list)
    serial_number: str = ""


class HttpProbe(BaseModel):
    url: str
    status_code: int
    title: str = ""
    content_length: int = 0
    tech: list[str] = Field(default_factory=list)
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
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    wildcard: bool = False


class TlsCert(BaseModel):
    host: str
    subject_cn: str = ""
    issuer: str = ""
    san: list[str] = Field(default_factory=list)
    not_after: str = ""
    expired: bool = False
    self_signed: bool = False


class ShodanHostInfo(BaseModel):
    ip: str = ""
    hostnames: list[str] = Field(default_factory=list)
    org: str = ""
    ports: list[int] = Field(default_factory=list)
    country: str = ""
    city: str = ""
    isp: str = ""
    vulns: list[str] = Field(default_factory=list)
    services: list[dict] = Field(default_factory=list)

class VirusTotalInfo(BaseModel):
    domain: str = ""
    reputation: int = 0
    malicious_count: int = 0
    harmless_count: int = 0
    dns_records: list[dict] = Field(default_factory=list)
    certificate_subject: str = ""
    certificate_issuer: str = ""

class SecurityTrailsInfo(BaseModel):
    hostname: str = ""
    a_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    subdomain_count: int = 0


class Screenshot(BaseModel):
    url: str
    final_url: str = ""
    status_code: int = 0
    title: str = ""
    filename: str = ""
    screenshot_path: str = ""
    response_time_ms: int = 0


class CensysServiceInfo(BaseModel):
    port: int = 0
    transport: str = ""
    service_name: str = ""
    banner: str = ""


class CensysHostInfo(BaseModel):
    ip: str = ""
    services: list[CensysServiceInfo] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    last_updated: str = ""
    total_results: int = 0


class ZoomEyeHostInfo(BaseModel):
    total: int = 0
    matches: list[dict] = Field(default_factory=list)   # ip, portinfo.port, geoinfo.country/city


class FofaHostInfo(BaseModel):
    total: int = 0
    results: list[dict] = Field(default_factory=list)   # ip, port, protocol, country, city, product


class GreyNoiseInfo(BaseModel):
    ip: str = ""
    noise: bool = False          # True = observed scanning the internet
    riot: bool = False           # True = known benign service (CDN, DNS, etc.)
    classification: str = ""     # benign | malicious | unknown
    name: str = ""               # e.g. "Cloudflare", "Google Public DNS"
    last_seen: str = ""
    message: str = ""


class ReconResult(BaseModel):
    """Aggregated result from recon module."""

    dns_records: list[DNSRecord] = Field(default_factory=list)
    subdomains: list[Subdomain] = Field(default_factory=list)
    whois_info: WhoisInfo | None = None
    certificate_info: CertificateInfo | None = None
    http_probes: list[HttpProbe] = Field(default_factory=list)
    crawl_results: list[CrawlResult] = Field(default_factory=list)
    historical_urls: list[HistoricalUrl] = Field(default_factory=list)
    dns_resolutions: list[DnsResolution] = Field(default_factory=list)
    tls_certs: list[TlsCert] = Field(default_factory=list)
    screenshots: list[Screenshot] = Field(default_factory=list)
    shodan_info: ShodanHostInfo | None = None
    virustotal_info: VirusTotalInfo | None = None
    securitytrails_info: SecurityTrailsInfo | None = None
    censys_info: CensysHostInfo | None = None
    zoomeye_info: ZoomEyeHostInfo | None = None
    fofa_info: FofaHostInfo | None = None
    greynoise_info: GreyNoiseInfo | None = None
