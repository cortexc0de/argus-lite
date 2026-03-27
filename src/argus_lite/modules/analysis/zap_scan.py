"""OWASP ZAP integration — spider, active scan, ajax spider.

ZAP runs as a daemon (Docker or local) with REST API.
Requires ZAP API key configured in config.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from argus_lite.models.finding import Finding, normalize_severity

logger = logging.getLogger(__name__)

DEFAULT_ZAP_URL = "http://127.0.0.1:8090"


async def zap_spider(target: str, api_url: str = DEFAULT_ZAP_URL, api_key: str = "") -> list[str]:
    """Run ZAP spider and return discovered URLs."""
    async with httpx.AsyncClient(timeout=300) as client:
        # Start spider
        resp = await client.get(
            f"{api_url}/JSON/spider/action/scan/",
            params={"url": target, "apikey": api_key},
        )
        scan_id = resp.json().get("scan", "0")

        # Poll until complete
        import asyncio
        for _ in range(120):
            status = await client.get(
                f"{api_url}/JSON/spider/view/status/",
                params={"scanId": scan_id, "apikey": api_key},
            )
            if int(status.json().get("status", "0")) >= 100:
                break
            await asyncio.sleep(2)

        # Get results
        results = await client.get(
            f"{api_url}/JSON/spider/view/results/",
            params={"scanId": scan_id, "apikey": api_key},
        )
        return results.json().get("results", [])


async def zap_active_scan(
    target: str,
    api_url: str = DEFAULT_ZAP_URL,
    api_key: str = "",
) -> list[Finding]:
    """Run ZAP active scan and return findings."""
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.get(
            f"{api_url}/JSON/ascan/action/scan/",
            params={"url": target, "apikey": api_key},
        )
        scan_id = resp.json().get("scan", "0")

        import asyncio
        for _ in range(300):
            status = await client.get(
                f"{api_url}/JSON/ascan/view/status/",
                params={"scanId": scan_id, "apikey": api_key},
            )
            if int(status.json().get("status", "0")) >= 100:
                break
            await asyncio.sleep(2)

        # Get alerts
        alerts_resp = await client.get(
            f"{api_url}/JSON/alert/view/alerts/",
            params={"baseurl": target, "apikey": api_key},
        )
        alerts = alerts_resp.json().get("alerts", [])

        return [_alert_to_finding(a) for a in alerts]


async def zap_ajax_spider(
    target: str,
    api_url: str = DEFAULT_ZAP_URL,
    api_key: str = "",
) -> list[str]:
    """Run ZAP AJAX spider (Playwright-based) for JS-heavy apps."""
    async with httpx.AsyncClient(timeout=300) as client:
        await client.get(
            f"{api_url}/JSON/ajaxSpider/action/scan/",
            params={"url": target, "apikey": api_key},
        )

        import asyncio
        for _ in range(120):
            status = await client.get(
                f"{api_url}/JSON/ajaxSpider/view/status/",
                params={"apikey": api_key},
            )
            if status.json().get("status") == "stopped":
                break
            await asyncio.sleep(2)

        results = await client.get(
            f"{api_url}/JSON/ajaxSpider/view/results/",
            params={"apikey": api_key, "start": "0", "count": "500"},
        )
        return [r.get("requestHeader", "").split(" ")[1]
                for r in results.json().get("results", [])
                if r.get("requestHeader")]


def _alert_to_finding(alert: dict[str, Any]) -> Finding:
    """Convert a ZAP alert to a Finding."""
    risk_map = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
    severity = risk_map.get(str(alert.get("risk", "0")), "INFO")

    return Finding(
        id=f"zap-{alert.get('pluginId', 'unknown')}-{alert.get('alertRef', '')}",
        type="zap",
        severity=severity,
        title=alert.get("name", "ZAP Alert"),
        description=alert.get("description", ""),
        asset=alert.get("url", ""),
        evidence=alert.get("evidence", "")[:200],
        source="zap",
        remediation=alert.get("solution", "Review and fix"),
    )
