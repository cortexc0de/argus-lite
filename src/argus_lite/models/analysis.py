"""Analysis module result models."""

from __future__ import annotations

from pydantic import BaseModel


class Port(BaseModel):
    port: int
    protocol: str  # tcp, udp
    service: str = ""
    banner: str = ""


class Technology(BaseModel):
    name: str
    version: str = ""
    category: str = ""  # cms, framework, server, language, etc.
    confidence: int = 100  # 0-100


class SSLInfo(BaseModel):
    protocol: str = ""  # TLSv1.2, TLSv1.3
    cipher: str = ""
    not_before: str = ""
    not_after: str = ""
    issuer: str = ""
    subject: str = ""
    expired: bool = False
    weak_cipher: bool = False


class SecurityHeadersResult(BaseModel):
    hsts: bool = False
    x_frame_options: bool = False
    x_content_type_options: bool = False
    csp: bool = False
    x_xss_protection: bool = False
    referrer_policy: bool = False
    permissions_policy: bool = False
    missing_headers: list[str] = []


class NucleiFinding(BaseModel):
    template_id: str
    name: str
    severity: str  # info, low — enforced at config level
    matched_at: str = ""
    description: str = ""
    reference: list[str] = []
    tags: list[str] = []


class FfufResult(BaseModel):
    url: str
    status_code: int
    content_length: int = 0
    words: int = 0
    lines: int = 0
    redirect_location: str = ""


class AnalysisResult(BaseModel):
    """Aggregated result from analysis module."""

    open_ports: list[Port] = []
    technologies: list[Technology] = []
    ssl_info: SSLInfo | None = None
    security_headers: SecurityHeadersResult | None = None
    nuclei_findings: list[NucleiFinding] = []
    fuzz_results: list[FfufResult] = []
