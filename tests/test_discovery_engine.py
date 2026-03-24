"""TDD: Tests for DiscoveryEngine — written BEFORE implementation."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.models.discover import DiscoverHost, DiscoverQuery, DiscoverResult


@pytest.fixture
def config():
    from argus_lite.core.config import AppConfig
    c = AppConfig()
    c.api_keys.shodan = "test-shodan-key"
    c.api_keys.censys_api_id = "test-censys-id"
    c.api_keys.censys_api_secret = "test-censys-secret"
    c.api_keys.zoomeye_api_key = "test-zoomeye-key"
    c.api_keys.fofa_email = "test@test.com"
    c.api_keys.fofa_api_key = "test-fofa-key"
    return c


@pytest.fixture
def engine(config):
    from argus_lite.core.discovery_engine import DiscoveryEngine
    return DiscoveryEngine(config)


class TestQueryBuilding:
    def test_build_shodan_cve_query(self, engine):
        q = DiscoverQuery(cve="CVE-2024-1234")
        result = engine._build_shodan_query(q)
        assert "vuln:CVE-2024-1234" in result

    def test_build_shodan_tech_query(self, engine):
        q = DiscoverQuery(tech="WordPress 6.3")
        result = engine._build_shodan_query(q)
        assert "wordpress" in result.lower()

    def test_build_shodan_port_country(self, engine):
        q = DiscoverQuery(port=3389, country="RU")
        result = engine._build_shodan_query(q)
        assert "port:3389" in result
        assert "country:RU" in result

    def test_build_censys_tech_query(self, engine):
        q = DiscoverQuery(tech="Apache 2.4")
        result = engine._build_censys_query(q)
        assert "apache" in result.lower()

    def test_build_zoomeye_query(self, engine):
        q = DiscoverQuery(tech="Nginx", country="US")
        result = engine._build_zoomeye_query(q)
        assert "nginx" in result.lower()

    def test_build_fofa_query(self, engine):
        q = DiscoverQuery(service="openssh")
        result = engine._build_fofa_query(q)
        assert "openssh" in result.lower()


class TestSearchSingle:
    def test_shodan_search_returns_hosts(self, engine):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [
                {"ip_str": "1.2.3.4", "port": 80, "product": "Apache",
                 "version": "2.4.51", "location": {"country_code": "US"},
                 "org": "Amazon"},
            ],
            "total": 1,
        }
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            hosts = asyncio.get_event_loop().run_until_complete(
                engine._search_shodan("port:80 product:apache")
            )
        assert len(hosts) == 1
        assert hosts[0].ip == "1.2.3.4"
        assert hosts[0].source == "shodan"

    def test_censys_search_returns_hosts(self, engine):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "result": {
                "hits": [
                    {"ip": "5.6.7.8", "services": [
                        {"port": 443, "service_name": "HTTPS", "software": [{"product": "nginx"}]}
                    ], "location": {"country": "DE"}},
                ],
                "total": 1,
            }
        }
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            hosts = asyncio.get_event_loop().run_until_complete(
                engine._search_censys("services.port:443")
            )
        assert len(hosts) >= 1
        assert hosts[0].source == "censys"

    def test_api_error_returns_empty(self, engine):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            hosts = asyncio.get_event_loop().run_until_complete(
                engine._search_shodan("test")
            )
        assert hosts == []


class TestDiscoverIntegration:
    def test_discover_deduplicates_by_ip(self, engine):
        host_a = DiscoverHost(ip="1.1.1.1", port=80, source="shodan")
        host_b = DiscoverHost(ip="1.1.1.1", port=443, source="censys")
        host_c = DiscoverHost(ip="2.2.2.2", port=80, source="fofa")

        deduped = engine._deduplicate([host_a, host_b, host_c])
        ips = [h.ip for h in deduped]
        assert ips.count("1.1.1.1") == 1
        assert "2.2.2.2" in ips

    def test_discover_with_all_apis_mocked(self, engine):
        async def mock_shodan(q):
            return [DiscoverHost(ip="1.1.1.1", port=80, source="shodan")]

        async def mock_censys(q):
            return [DiscoverHost(ip="2.2.2.2", port=443, source="censys")]

        async def mock_zoomeye(q):
            return [DiscoverHost(ip="3.3.3.3", port=22, source="zoomeye")]

        async def mock_fofa(q):
            return [DiscoverHost(ip="1.1.1.1", port=8080, source="fofa")]  # duplicate IP

        with patch.object(engine, "_search_shodan", mock_shodan), \
             patch.object(engine, "_search_censys", mock_censys), \
             patch.object(engine, "_search_zoomeye", mock_zoomeye), \
             patch.object(engine, "_search_fofa", mock_fofa):

            q = DiscoverQuery(tech="WordPress")
            result = asyncio.get_event_loop().run_until_complete(engine.discover(q))

        assert result.total_found == 3  # 4 results, 1 duplicate removed
        assert len(result.sources_queried) == 4

    def test_discover_skips_apis_without_keys(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.core.discovery_engine import DiscoveryEngine

        config = AppConfig()  # no API keys set
        engine = DiscoveryEngine(config)

        q = DiscoverQuery(cve="CVE-2024-0001")
        result = asyncio.get_event_loop().run_until_complete(engine.discover(q))
        assert result.total_found == 0
        assert len(result.sources_queried) == 0

    def test_empty_query_returns_empty(self, engine):
        q = DiscoverQuery()  # all fields empty
        result = asyncio.get_event_loop().run_until_complete(engine.discover(q))
        assert result.total_found == 0
