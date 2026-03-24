"""Threat Intelligence Feed — CVE subscriptions and auto-notifications."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from argus_lite.models.finding import Vulnerability

logger = logging.getLogger(__name__)

_NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_recent_cves(
    keywords: list[str],
    days: int = 7,
    api_key: str = "",
    max_results: int = 20,
) -> list[Vulnerability]:
    """Fetch recent CVEs from NVD matching keywords.

    Keywords are technologies you're tracking (e.g., "WordPress", "Apache").
    Returns CVEs published in the last N days.
    """
    if not keywords:
        return []

    from datetime import timedelta

    now = datetime.now(tz=timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")

    all_vulns: list[Vulnerability] = []

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    for keyword in keywords[:10]:  # Limit to 10 keywords
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": min(max_results, 20),
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(_NVD_RECENT_URL, params=params, headers=headers)
            if resp.status_code != 200:
                logger.debug("NVD returned %s for keyword '%s'", resp.status_code, keyword)
                continue
            data = resp.json()
        except Exception as exc:
            logger.debug("NVD fetch failed for '%s': %s", keyword, exc)
            continue

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Parse CVSS score
            score = None
            vector = None
            metrics = cve_data.get("metrics", {})
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(mk, [])
                if entries:
                    cvss = entries[0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    vector = cvss.get("vectorString")
                    break

            import uuid
            all_vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                finding_id="",
                cve=cve_id,
                cvss_score=score,
                cvss_vector=vector,
                references=[r.get("url", "") for r in cve_data.get("references", [])[:3]],
            ))

        # Rate limit: sleep between keywords
        import asyncio
        await asyncio.sleep(0.6 if api_key else 6.0)

    return all_vulns


async def check_threat_feed(
    technologies: list[str],
    api_key: str = "",
    days: int = 7,
) -> dict:
    """Check threat feed for technologies in your stack.

    Returns summary with new CVEs relevant to your tech.
    """
    vulns = await fetch_recent_cves(technologies, days=days, api_key=api_key)

    critical = [v for v in vulns if v.cvss_score and v.cvss_score >= 9.0]
    high = [v for v in vulns if v.cvss_score and 7.0 <= v.cvss_score < 9.0]

    return {
        "technologies_checked": technologies,
        "period_days": days,
        "total_cves": len(vulns),
        "critical_count": len(critical),
        "high_count": len(high),
        "cves": vulns,
        "critical_cves": critical,
    }
