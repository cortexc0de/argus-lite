"""VirusTotal API integration."""
from __future__ import annotations
import json
import httpx
from argus_lite.models.recon import VirusTotalInfo

def parse_vt_response(raw_json: str) -> VirusTotalInfo:
    if not raw_json.strip():
        return VirusTotalInfo()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return VirusTotalInfo()

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    cert = attrs.get("last_https_certificate", {})
    cert_subject = cert.get("subject", {}).get("CN", "")
    cert_issuer = cert.get("issuer", {}).get("O", "")

    return VirusTotalInfo(
        domain=data.get("data", {}).get("id", ""),
        reputation=attrs.get("reputation", 0),
        malicious_count=stats.get("malicious", 0),
        harmless_count=stats.get("harmless", 0),
        dns_records=attrs.get("last_dns_records", []),
        certificate_subject=cert_subject,
        certificate_issuer=cert_issuer,
    )

async def vt_lookup(target: str, api_key: str) -> VirusTotalInfo:
    if not api_key:
        return VirusTotalInfo()
    url = f"https://www.virustotal.com/api/v3/domains/{target}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"x-apikey": api_key})
        if resp.status_code != 200:
            return VirusTotalInfo()
        return parse_vt_response(resp.text)
