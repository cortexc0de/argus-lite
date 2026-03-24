"""Vulnerability Discovery Engine — find hosts by CVE, tech, service across OSINT APIs."""

from __future__ import annotations

import asyncio
import logging

import httpx

from argus_lite.core.config import AppConfig
from argus_lite.models.discover import DiscoverHost, DiscoverQuery, DiscoverResult

logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Query multiple OSINT platforms in parallel to find vulnerable hosts."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._keys = config.api_keys

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def discover(self, query: DiscoverQuery) -> DiscoverResult:
        """Run query against all configured OSINT APIs, deduplicate results."""
        if not query.cve and not query.tech and not query.service and not query.port:
            return DiscoverResult(query=query)

        tasks: list[tuple[str, asyncio.Task]] = []
        sources_queried: list[str] = []
        sources_failed: list[str] = []

        # Build per-platform queries and search
        if self._keys.shodan:
            q = self._build_shodan_query(query)
            tasks.append(("shodan", self._search_shodan(q)))
            sources_queried.append("shodan")

        if self._keys.censys_api_id and self._keys.censys_api_secret:
            q = self._build_censys_query(query)
            tasks.append(("censys", self._search_censys(q)))
            sources_queried.append("censys")

        if self._keys.zoomeye_api_key:
            q = self._build_zoomeye_query(query)
            tasks.append(("zoomeye", self._search_zoomeye(q)))
            sources_queried.append("zoomeye")

        if self._keys.fofa_email and self._keys.fofa_api_key:
            q = self._build_fofa_query(query)
            tasks.append(("fofa", self._search_fofa(q)))
            sources_queried.append("fofa")

        if not tasks:
            return DiscoverResult(query=query)

        # Run all searches in parallel
        all_hosts: list[DiscoverHost] = []
        coros = [t[1] for t in tasks]
        names = [t[0] for t in tasks]

        results = await asyncio.gather(*coros, return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                logger.warning("Discovery search failed for %s: %s", name, result)
                sources_failed.append(name)
            else:
                all_hosts.extend(result)

        deduped = self._deduplicate(all_hosts)

        return DiscoverResult(
            query=query,
            hosts=deduped,
            total_found=len(deduped),
            sources_queried=sources_queried,
            sources_failed=sources_failed,
        )

    # ------------------------------------------------------------------
    # Query builders (per platform)
    # ------------------------------------------------------------------

    def _build_shodan_query(self, q: DiscoverQuery) -> str:
        parts = []
        if q.cve:
            parts.append(f"vuln:{q.cve}")
        if q.tech:
            parts.append(f'product:"{q.tech.split()[0]}"')
            if len(q.tech.split()) > 1:
                parts.append(f'version:"{" ".join(q.tech.split()[1:])}"')
        if q.service:
            parts.append(f'product:"{q.service}"')
        if q.port:
            parts.append(f"port:{q.port}")
        if q.country:
            parts.append(f"country:{q.country}")
        return " ".join(parts)

    def _build_censys_query(self, q: DiscoverQuery) -> str:
        parts = []
        if q.cve:
            parts.append(f"services.software.cpe:*{q.cve.lower()}*")
        if q.tech:
            name = q.tech.split()[0]
            parts.append(f"services.software.product:{name}")
        if q.service:
            parts.append(f"services.service_name:{q.service}")
        if q.port:
            parts.append(f"services.port:{q.port}")
        if q.country:
            parts.append(f"location.country_code:{q.country}")
        return " AND ".join(parts)

    def _build_zoomeye_query(self, q: DiscoverQuery) -> str:
        parts = []
        if q.cve:
            parts.append(f"vuln:{q.cve}")
        if q.tech:
            parts.append(f"app:{q.tech.split()[0]}")
        if q.service:
            parts.append(f"service:{q.service}")
        if q.port:
            parts.append(f"port:{q.port}")
        if q.country:
            parts.append(f"country:{q.country}")
        return " ".join(parts) if parts else "+".join(parts)

    def _build_fofa_query(self, q: DiscoverQuery) -> str:
        parts = []
        if q.tech:
            parts.append(f'app="{q.tech.split()[0]}"')
        if q.service:
            parts.append(f'protocol="{q.service}"')
        if q.port:
            parts.append(f'port="{q.port}"')
        if q.country:
            parts.append(f'country="{q.country}"')
        if q.cve:
            parts.append(f'body="{q.cve}"')
        return " && ".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # Platform-specific search functions
    # ------------------------------------------------------------------

    async def _search_shodan(self, query: str, max_results: int = 100) -> list[DiscoverHost]:
        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": self._keys.shodan, "query": query, "minify": True}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params)
            if resp.status_code != 200:
                logger.debug("Shodan search returned %s", resp.status_code)
                return []
            data = resp.json()
        except Exception as exc:
            logger.debug("Shodan search error: %s", exc)
            return []

        hosts = []
        for m in data.get("matches", [])[:max_results]:
            hosts.append(DiscoverHost(
                ip=m.get("ip_str", ""),
                port=m.get("port", 0),
                service=m.get("transport", ""),
                product=m.get("product", ""),
                version=m.get("version", ""),
                country=m.get("location", {}).get("country_code", ""),
                org=m.get("org", ""),
                source="shodan",
            ))
        return hosts

    async def _search_censys(self, query: str, max_results: int = 100) -> list[DiscoverHost]:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": query, "per_page": min(max_results, 100)}
        auth = (self._keys.censys_api_id, self._keys.censys_api_secret)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params, auth=auth)
            if resp.status_code != 200:
                logger.debug("Censys search returned %s", resp.status_code)
                return []
            data = resp.json()
        except Exception as exc:
            logger.debug("Censys search error: %s", exc)
            return []

        hosts = []
        for hit in data.get("result", {}).get("hits", [])[:max_results]:
            ip = hit.get("ip", "")
            country = hit.get("location", {}).get("country", "")
            for svc in hit.get("services", []):
                hosts.append(DiscoverHost(
                    ip=ip,
                    port=svc.get("port", 0),
                    service=svc.get("service_name", ""),
                    product=(svc.get("software", [{}])[0].get("product", "")
                             if svc.get("software") else ""),
                    country=country,
                    source="censys",
                ))
                break  # one host entry per IP
            if not hit.get("services"):
                hosts.append(DiscoverHost(ip=ip, country=country, source="censys"))
        return hosts

    async def _search_zoomeye(self, query: str, max_results: int = 100) -> list[DiscoverHost]:
        url = "https://api.zoomeye.org/host/search"
        params = {"query": query, "page": 1}
        headers = {"Authorization": f"JWT {self._keys.zoomeye_api_key}"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                logger.debug("ZoomEye search returned %s", resp.status_code)
                return []
            data = resp.json()
        except Exception as exc:
            logger.debug("ZoomEye search error: %s", exc)
            return []

        hosts = []
        for m in data.get("matches", [])[:max_results]:
            hosts.append(DiscoverHost(
                ip=m.get("ip", ""),
                port=m.get("portinfo", {}).get("port", 0),
                service=m.get("portinfo", {}).get("service", ""),
                product=m.get("portinfo", {}).get("product", ""),
                country=m.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                source="zoomeye",
            ))
        return hosts

    async def _search_fofa(self, query: str, max_results: int = 100) -> list[DiscoverHost]:
        import base64
        url = "https://fofa.info/api/v1/search/all"
        qbase64 = base64.b64encode(query.encode()).decode()
        params = {
            "email": self._keys.fofa_email,
            "key": self._keys.fofa_api_key,
            "qbase64": qbase64,
            "fields": "ip,port,protocol,country,product",
            "size": min(max_results, 1000),
            "page": 1,
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params)
            if resp.status_code != 200:
                logger.debug("FOFA search returned %s", resp.status_code)
                return []
            data = resp.json()
            if data.get("error"):
                logger.debug("FOFA error: %s", data.get("errmsg", ""))
                return []
        except Exception as exc:
            logger.debug("FOFA search error: %s", exc)
            return []

        field_names = ["ip", "port", "protocol", "country", "product"]
        hosts = []
        for row in data.get("results", [])[:max_results]:
            if isinstance(row, list):
                d = dict(zip(field_names, row))
            else:
                d = row
            hosts.append(DiscoverHost(
                ip=d.get("ip", ""),
                port=int(d.get("port", 0) or 0),
                service=d.get("protocol", ""),
                product=d.get("product", ""),
                country=d.get("country", ""),
                source="fofa",
            ))
        return hosts

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate(self, hosts: list[DiscoverHost]) -> list[DiscoverHost]:
        """Deduplicate by IP, keeping the first occurrence."""
        seen: set[str] = set()
        result: list[DiscoverHost] = []
        for h in hosts:
            if h.ip and h.ip not in seen:
                seen.add(h.ip)
                result.append(h)
        return result
