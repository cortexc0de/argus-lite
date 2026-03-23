"""GreyNoise API v3 integration (Community + Enterprise)."""

from __future__ import annotations

import logging
import socket

import httpx

from argus_lite.models.recon import GreyNoiseInfo

logger = logging.getLogger(__name__)

# Community endpoint (free, limited to IP lookup)
_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
# Enterprise endpoint (full context, requires paid key)
_ENTERPRISE_URL = "https://api.greynoise.io/v3/ip"


def parse_greynoise_response(data: dict) -> GreyNoiseInfo:
    """Parse GreyNoise /v3/community/{ip} or /v3/ip/{ip} response."""
    if not data:
        return GreyNoiseInfo()

    return GreyNoiseInfo(
        ip=data.get("ip", ""),
        noise=bool(data.get("noise", False)),
        riot=bool(data.get("riot", False)),
        classification=data.get("classification", ""),
        name=data.get("name", ""),
        last_seen=data.get("last_seen", ""),
        message=data.get("message", ""),
    )


async def greynoise_lookup(target: str, api_key: str = "") -> GreyNoiseInfo:
    """Look up IP reputation on GreyNoise.

    Without api_key: uses free Community endpoint (10 lookups/day).
    With api_key: uses Enterprise endpoint for full context.
    """
    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    # Choose endpoint based on key availability
    url = f"{_ENTERPRISE_URL}/{ip}" if api_key else f"{_COMMUNITY_URL}/{ip}"
    headers: dict[str, str] = {}
    if api_key:
        headers["key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.debug("GreyNoise returned %s for %s", resp.status_code, ip)
            return GreyNoiseInfo()
        return parse_greynoise_response(resp.json())
    except Exception as exc:
        logger.debug("GreyNoise lookup failed for %s: %s", target, exc)
        return GreyNoiseInfo()
