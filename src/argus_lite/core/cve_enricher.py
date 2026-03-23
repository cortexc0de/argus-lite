"""CVE enrichment via NVD (National Vulnerability Database) API v2.0."""

from __future__ import annotations

import asyncio
import logging
import uuid

import httpx

from argus_lite.models.analysis import Technology
from argus_lite.models.finding import Vulnerability

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits: 5 req / 30s without key (~6s/req), 50 req / 30s with key (~0.6s/req)
_SLEEP_NO_KEY = 6.0
_SLEEP_WITH_KEY = 0.6


class CveEnricher:
    """Query NVD API for CVEs matching detected technologies."""

    def __init__(self, api_key: str = "", timeout: int = 30) -> None:
        self._api_key = api_key
        self._timeout = timeout

    async def enrich(self, technologies: list[Technology]) -> list[Vulnerability]:
        """Enrich a list of technologies with CVE data from NVD.

        Only queries technologies that have a non-empty version field.
        Returns a flat list of Vulnerability objects across all techs.
        Gracefully returns [] on any error.
        """
        results: list[Vulnerability] = []
        for tech in technologies:
            if not tech.version:
                continue
            vulns = await self._query_cve(tech)
            results.extend(vulns)
        return results

    async def _query_cve(self, tech: Technology) -> list[Vulnerability]:
        """Query NVD for a single technology. Returns [] on any error."""
        keyword = f"{tech.name} {tech.version}"
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        # Respect NVD rate limits
        sleep_time = _SLEEP_WITH_KEY if self._api_key else _SLEEP_NO_KEY
        await asyncio.sleep(sleep_time)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(_NVD_BASE_URL, params=params, headers=headers)

            if resp.status_code != 200:
                logger.debug("NVD API returned %s for %s", resp.status_code, keyword)
                return []

            data = resp.json()
        except httpx.TimeoutException:
            logger.debug("NVD API timeout for %s", keyword)
            return []
        except Exception as exc:
            logger.debug("NVD API error for %s: %s", keyword, exc)
            return []

        return self._parse_vulnerabilities(data)

    def _parse_vulnerabilities(self, data: dict) -> list[Vulnerability]:
        """Parse NVD API response into Vulnerability objects."""
        vulns: list[Vulnerability] = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            score, vector = self._parse_cvss(cve_data)

            refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]

            vulns.append(
                Vulnerability(
                    id=str(uuid.uuid4()),
                    finding_id="",
                    cve=cve_id,
                    cvss_score=score,
                    cvss_vector=vector,
                    references=refs,
                )
            )
        return vulns

    def _parse_cvss(self, cve_data: dict) -> tuple[float | None, str | None]:
        """Extract CVSS score and vector. Tries V3.1 → V3.0 → V2."""
        metrics = cve_data.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                return score, vector

        return None, None
