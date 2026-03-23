"""Censys Search API v2 integration."""

from __future__ import annotations

import logging

import httpx

from argus_lite.models.recon import CensysHostInfo, CensysServiceInfo

logger = logging.getLogger(__name__)

_BASE_URL = "https://search.censys.io/api/v2"


def parse_censys_host_response(data: dict) -> CensysHostInfo:
    """Parse Censys /v2/hosts/{ip} response into CensysHostInfo."""
    result = data.get("result", {})
    if not result:
        return CensysHostInfo()

    services = []
    for svc in result.get("services", []):
        services.append(CensysServiceInfo(
            port=svc.get("port", 0),
            transport=svc.get("transport_protocol", ""),
            service_name=svc.get("service_name", ""),
            banner=(svc.get("banner", "") or "")[:200],
        ))

    return CensysHostInfo(
        ip=result.get("ip", ""),
        services=services,
        labels=result.get("labels", []),
        last_updated=result.get("last_updated_at", ""),
        total_results=1,
    )


def parse_censys_search_response(data: dict) -> list[str]:
    """Parse Censys /v2/hosts/search response → list of IPs."""
    result = data.get("result", {})
    hits = result.get("hits", [])
    return [h.get("ip", "") for h in hits if h.get("ip")]


async def censys_lookup(target: str, api_id: str, api_secret: str) -> CensysHostInfo:
    """Look up a host on Censys by IP or domain. Returns CensysHostInfo."""
    if not api_id or not api_secret:
        return CensysHostInfo()

    # Resolve domain to IP if needed
    import socket
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    url = f"{_BASE_URL}/hosts/{ip}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, auth=(api_id, api_secret))
        if resp.status_code != 200:
            logger.debug("Censys returned %s for %s", resp.status_code, ip)
            return CensysHostInfo()
        return parse_censys_host_response(resp.json())
    except Exception as exc:
        logger.debug("Censys lookup failed for %s: %s", target, exc)
        return CensysHostInfo()


async def censys_search(query: str, api_id: str, api_secret: str,
                        max_results: int = 100) -> list[str]:
    """Search Censys with a query string → list of IP addresses."""
    if not api_id or not api_secret:
        return []

    url = f"{_BASE_URL}/hosts/search"
    params = {"q": query, "per_page": min(max_results, 100)}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params, auth=(api_id, api_secret))
        if resp.status_code != 200:
            logger.debug("Censys search returned %s", resp.status_code)
            return []
        return parse_censys_search_response(resp.json())
    except Exception as exc:
        logger.debug("Censys search failed: %s", exc)
        return []
