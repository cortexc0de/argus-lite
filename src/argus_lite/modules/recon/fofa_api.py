"""FOFA API integration (fofa.info)."""

from __future__ import annotations

import base64
import logging

import httpx

from argus_lite.models.recon import FofaHostInfo

logger = logging.getLogger(__name__)

_BASE_URL = "https://fofa.info"
# Default fields to retrieve
_FIELDS = "ip,port,protocol,country,city,product"


def parse_fofa_response(data: dict) -> FofaHostInfo:
    """Parse FOFA /api/v1/search/all response."""
    if not data or data.get("error"):
        return FofaHostInfo()

    field_names = _FIELDS.split(",")
    results = []
    for row in data.get("results", []):
        if isinstance(row, list):
            results.append(dict(zip(field_names, row)))
        elif isinstance(row, dict):
            results.append(row)

    return FofaHostInfo(
        total=data.get("size", len(results)),
        results=results,
    )


async def fofa_lookup(target: str, email: str, api_key: str) -> FofaHostInfo:
    """Look up a domain/IP on FOFA. Returns FofaHostInfo."""
    if not email or not api_key:
        return FofaHostInfo()

    query = f'domain="{target}"'
    return await _fofa_query(query, email=email, api_key=api_key)


async def fofa_search(query: str, email: str, api_key: str,
                      max_results: int = 100) -> list[str]:
    """Search FOFA with arbitrary query → list of IP addresses."""
    if not email or not api_key:
        return []

    info = await _fofa_query(query, email=email, api_key=api_key, size=max_results)
    return list({r.get("ip", "") for r in info.results if r.get("ip")})


async def _fofa_query(query: str, email: str, api_key: str,
                      size: int = 100) -> FofaHostInfo:
    """Internal: run a FOFA query with base64-encoded query string."""
    qbase64 = base64.b64encode(query.encode()).decode()
    url = f"{_BASE_URL}/api/v1/search/all"
    params = {
        "email": email,
        "key": api_key,
        "qbase64": qbase64,
        "fields": _FIELDS,
        "size": min(size, 1000),
        "page": 1,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params)
        if resp.status_code != 200:
            logger.debug("FOFA returned %s for query: %s", resp.status_code, query)
            return FofaHostInfo()
        return parse_fofa_response(resp.json())
    except Exception as exc:
        logger.debug("FOFA query failed: %s", exc)
        return FofaHostInfo()
