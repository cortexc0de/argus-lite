"""OWASP ZAP integration — spider, active scan, ajax spider.

ZAP runs as a daemon (Docker or local) with REST API.
Requires ZAP API key configured in config.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from argus_lite.models.finding import Finding

logger = logging.getLogger(__name__)

DEFAULT_ZAP_URL = "http://127.0.0.1:8090"


async def _poll_zap_status(
    client: httpx.AsyncClient,
    status_url: str,
    params: dict[str, str],
    label: str,
    max_polls: int = 120,
    done_value: int | str = 100,
    done_key: str = "status",
) -> None:
    """Poll a ZAP status endpoint until complete, error, or timeout."""
    for _ in range(max_polls):
        resp = await client.get(status_url, params=params)
        raw = resp.json().get(done_key, "0")

        # Numeric status (spider/ascan): 0..100, <0 = error
        if isinstance(done_value, int):
            progress = int(raw)
            if progress >= done_value:
                return
            if progress < 0:
                logger.warning("ZAP %s error state: %s", label, resp.text[:200])
                return
        # String status (ajax spider): "stopped"
        elif raw == done_value:
            return

        await asyncio.sleep(2)

    logger.warning("ZAP %s timeout after %d poll attempts", label, max_polls)


async def zap_spider(target: str, api_url: str = DEFAULT_ZAP_URL, api_key: str = "") -> list[str]:
    """Run ZAP spider and return discovered URLs."""
    async with httpx.AsyncClient(timeout=300) as client:
        resp = await client.get(
            f"{api_url}/JSON/spider/action/scan/",
            params={"url": target, "apikey": api_key},
        )
        scan_id = resp.json().get("scan", "0")

        await _poll_zap_status(
            client, f"{api_url}/JSON/spider/view/status/",
            {"scanId": scan_id, "apikey": api_key}, "spider",
        )

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

        await _poll_zap_status(
            client, f"{api_url}/JSON/ascan/view/status/",
            {"scanId": scan_id, "apikey": api_key}, "active_scan",
            max_polls=300,
        )

        alerts_resp = await client.get(
            f"{api_url}/JSON/alert/view/alerts/",
            params={"baseurl": target, "apikey": api_key},
        )
        if alerts_resp.status_code != 200:
            logger.error("ZAP alerts query failed: %d", alerts_resp.status_code)
            return []
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

        await _poll_zap_status(
            client, f"{api_url}/JSON/ajaxSpider/view/status/",
            {"apikey": api_key}, "ajax_spider",
            done_value="stopped",
        )

        results = await client.get(
            f"{api_url}/JSON/ajaxSpider/view/results/",
            params={"apikey": api_key, "start": "0", "count": "500"},
        )
        return [
            r.get("requestHeader", "").split(" ")[1]
            for r in results.json().get("results", [])
            if r.get("requestHeader")
        ]


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
