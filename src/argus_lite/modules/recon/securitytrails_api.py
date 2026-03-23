"""SecurityTrails API integration."""
from __future__ import annotations
import json
import httpx
from argus_lite.models.recon import SecurityTrailsInfo

def parse_st_response(raw_json: str) -> SecurityTrailsInfo:
    if not raw_json.strip():
        return SecurityTrailsInfo()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return SecurityTrailsInfo()

    dns = data.get("current_dns", {})

    a_records = [v.get("ip", "") for v in dns.get("a", {}).get("values", [])]
    mx_records = [v.get("host", "") for v in dns.get("mx", {}).get("values", [])]
    ns_records = [v.get("nameserver", "") for v in dns.get("ns", {}).get("values", [])]

    return SecurityTrailsInfo(
        hostname=data.get("hostname", ""),
        a_records=a_records,
        mx_records=mx_records,
        ns_records=ns_records,
        subdomain_count=data.get("subdomain_count", 0),
    )

async def st_lookup(target: str, api_key: str) -> SecurityTrailsInfo:
    if not api_key:
        return SecurityTrailsInfo()
    url = f"https://api.securitytrails.com/v1/domain/{target}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"APIKEY": api_key})
        if resp.status_code != 200:
            return SecurityTrailsInfo()
        return parse_st_response(resp.text)
