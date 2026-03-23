"""Shodan API integration."""
from __future__ import annotations
import json
import httpx
from argus_lite.models.recon import ShodanHostInfo

def parse_shodan_response(raw_json: str) -> ShodanHostInfo:
    if not raw_json.strip():
        return ShodanHostInfo()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ShodanHostInfo()

    services = []
    for svc in data.get("data", []):
        services.append({
            "port": svc.get("port"),
            "transport": svc.get("transport", ""),
            "product": svc.get("product", ""),
            "banner": svc.get("banner", "")[:200],
        })

    return ShodanHostInfo(
        ip=data.get("ip_str", ""),
        hostnames=data.get("hostnames", []),
        org=data.get("org", ""),
        ports=data.get("ports", []),
        country=data.get("country_code", ""),
        city=data.get("city", ""),
        isp=data.get("isp", ""),
        vulns=data.get("vulns", []),
        services=services,
    )

async def shodan_lookup(target: str, api_key: str) -> ShodanHostInfo:
    if not api_key:
        return ShodanHostInfo()
    # Resolve domain to IP first if needed
    import socket
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            return ShodanHostInfo()
        return parse_shodan_response(resp.text)
