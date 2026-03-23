"""ZoomEye API v2 integration."""

from __future__ import annotations

import logging

import httpx

from argus_lite.models.recon import ZoomEyeHostInfo

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.zoomeye.org"


def parse_zoomeye_response(data: dict) -> ZoomEyeHostInfo:
    """Parse ZoomEye /host/search response."""
    if not data:
        return ZoomEyeHostInfo()

    matches = []
    for m in data.get("matches", []):
        matches.append({
            "ip": m.get("ip", ""),
            "port": m.get("portinfo", {}).get("port", 0),
            "service": m.get("portinfo", {}).get("service", ""),
            "country": m.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
            "city": m.get("geoinfo", {}).get("city", {}).get("names", {}).get("en", ""),
        })

    return ZoomEyeHostInfo(
        total=data.get("total", 0),
        matches=matches,
    )


async def zoomeye_lookup(target: str, api_key: str) -> ZoomEyeHostInfo:
    """Look up a host on ZoomEye. Returns ZoomEyeHostInfo."""
    if not api_key:
        return ZoomEyeHostInfo()

    url = f"{_BASE_URL}/host/search"
    params = {"query": f"hostname:{target}", "page": 1}
    headers = {"Authorization": f"JWT {api_key}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("ZoomEye returned %s for %s", resp.status_code, target)
            return ZoomEyeHostInfo()
        return parse_zoomeye_response(resp.json())
    except Exception as exc:
        logger.debug("ZoomEye lookup failed for %s: %s", target, exc)
        return ZoomEyeHostInfo()


async def zoomeye_search(query: str, api_key: str, max_results: int = 100) -> list[str]:
    """Search ZoomEye with a dork → list of IP addresses."""
    if not api_key:
        return []

    url = f"{_BASE_URL}/host/search"
    params = {"query": query, "page": 1}
    headers = {"Authorization": f"JWT {api_key}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("ZoomEye search returned %s", resp.status_code)
            return []
        data = parse_zoomeye_response(resp.json())
        return [m["ip"] for m in data.matches if m.get("ip")][:max_results]
    except Exception as exc:
        logger.debug("ZoomEye search failed: %s", exc)
        return []
