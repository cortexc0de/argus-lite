"""Target expansion — converts files/CIDRs/ASNs/Shodan queries to target lists."""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

import httpx

from argus_lite.core.config import AppConfig

logger = logging.getLogger(__name__)

_ASN_RE = re.compile(r"^[Aa][Ss]\d+$")
_CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
_BGPVIEW_URL = "https://api.bgpview.io/asn/{asn}/prefixes"


class TargetExpander:
    """Expand source specs into a flat, deduplicated list of scan targets."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._max_targets: int = config.bulk.max_targets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def expand(self, sources: list[str]) -> list[str]:
        """Expand mixed source list → deduplicated targets (≤ max_targets)."""
        seen: set[str] = set()
        result: list[str] = []

        for source in sources:
            kind = self._detect_source_type(source)

            if kind == "file":
                targets = self._expand_file(source)
            elif kind == "cidr":
                targets = self._expand_cidr(source)
            elif kind == "asn":
                targets = await self._expand_asn(source)
            elif kind == "host":
                targets = [source]
            else:
                # shodan — skip unless explicitly called via expand_shodan()
                logger.warning(
                    "Source '%s' looks like a Shodan query — use --shodan flag", source
                )
                continue

            for t in targets:
                t = t.strip()
                if t and t not in seen:
                    seen.add(t)
                    result.append(t)
                    if len(result) >= self._max_targets:
                        logger.info("Reached max_targets=%d, stopping expansion", self._max_targets)
                        return result

        return result

    async def expand_shodan(self, query: str) -> list[str]:
        """Expand a Shodan search query → list of IP addresses."""
        return await self._expand_shodan(query)

    async def expand_censys(self, query: str) -> list[str]:
        """Expand a Censys search query → list of IP addresses."""
        from argus_lite.modules.recon.censys_api import censys_search
        keys = self._config.api_keys
        if not keys.censys_api_id or not keys.censys_api_secret:
            logger.warning("Censys search requires ARGUS_CENSYS_ID + ARGUS_CENSYS_SECRET")
            return []
        results = await censys_search(query, api_id=keys.censys_api_id,
                                      api_secret=keys.censys_api_secret,
                                      max_results=self._max_targets)
        return results[:self._max_targets]

    async def expand_zoomeye(self, query: str) -> list[str]:
        """Expand a ZoomEye dork → list of IP addresses."""
        from argus_lite.modules.recon.zoomeye_api import zoomeye_search
        api_key = self._config.api_keys.zoomeye_api_key
        if not api_key:
            logger.warning("ZoomEye search requires ARGUS_ZOOMEYE_KEY")
            return []
        results = await zoomeye_search(query, api_key=api_key,
                                       max_results=self._max_targets)
        return results[:self._max_targets]

    async def expand_fofa(self, query: str) -> list[str]:
        """Expand a FOFA query → list of IP addresses."""
        from argus_lite.modules.recon.fofa_api import fofa_search
        keys = self._config.api_keys
        if not keys.fofa_email or not keys.fofa_api_key:
            logger.warning("FOFA search requires ARGUS_FOFA_EMAIL + ARGUS_FOFA_KEY")
            return []
        results = await fofa_search(query, email=keys.fofa_email,
                                    api_key=keys.fofa_api_key,
                                    max_results=self._max_targets)
        return results[:self._max_targets]

    # ------------------------------------------------------------------
    # Source type detection
    # ------------------------------------------------------------------

    def _detect_source_type(self, source: str) -> str:
        """Detect the type of a source string."""
        # File path — must exist
        if Path(source).exists():
            return "file"
        # CIDR notation
        if _CIDR_RE.match(source):
            return "cidr"
        # ASN (AS12345 or as12345)
        if _ASN_RE.match(source):
            return "asn"
        # Plain host: domain or IP (no spaces)
        if " " not in source and "/" not in source:
            return "host"
        # Everything else treated as potential Shodan query
        return "shodan"

    # ------------------------------------------------------------------
    # Expanders
    # ------------------------------------------------------------------

    def _expand_file(self, path: str) -> list[str]:
        """Read targets from a file (one per line, skip # comments)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Target file not found: {path}")

        targets: list[str] = []
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
        return targets

    def _expand_cidr(self, cidr: str) -> list[str]:
        """Expand CIDR notation to a list of individual IPs.

        Does NOT apply max_targets cap — that happens in expand() globally.
        Caps at 65536 to prevent accidental /8 expansions.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR '{cidr}': {e}") from e

        hosts = list(network.hosts())
        if not hosts:
            # /32 or single host — include the network address itself
            hosts = [network.network_address]

        # Hard safety cap (e.g. /8 would be 16M IPs)
        _HARD_CAP = 65536
        return [str(ip) for ip in hosts[:_HARD_CAP]]

    async def _expand_asn(self, asn: str) -> list[str]:
        """Expand ASN to IPs via BGPView API (free, no API key needed)."""
        asn_num = asn.upper().lstrip("AS")
        url = _BGPVIEW_URL.format(asn=asn_num)

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning("BGPView returned %s for ASN %s", resp.status_code, asn)
                return []
            data = resp.json()
        except Exception as exc:
            logger.warning("ASN expansion failed for %s: %s", asn, exc)
            return []

        prefixes = data.get("data", {}).get("ipv4_prefixes", [])
        targets: list[str] = []
        for prefix_entry in prefixes:
            cidr = prefix_entry.get("prefix", "")
            if cidr:
                try:
                    expanded = self._expand_cidr(cidr)
                    targets.extend(expanded)
                    if len(targets) >= self._max_targets:
                        return targets[: self._max_targets]
                except ValueError:
                    continue
        return targets[: self._max_targets]

    async def _expand_shodan(self, query: str) -> list[str]:
        """Expand Shodan search query to list of IPs."""
        api_key = self._config.api_keys.shodan
        if not api_key:
            logger.warning("Shodan query expansion requires ARGUS_SHODAN_KEY")
            return []

        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": api_key, "query": query, "minify": True}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, params=params)
            if resp.status_code != 200:
                logger.warning("Shodan search returned %s", resp.status_code)
                return []
            data = resp.json()
        except Exception as exc:
            logger.warning("Shodan expansion failed: %s", exc)
            return []

        matches = data.get("matches", [])
        targets = [m.get("ip_str", "") for m in matches if m.get("ip_str")]
        return list(dict.fromkeys(targets))[: self._max_targets]
