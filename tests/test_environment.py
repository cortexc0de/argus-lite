"""TDD: Tests for Environment Detection."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestWafDetection:
    def test_detect_cloudflare(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        waf = d._detect_waf(
            {"cf-ray": "abc123", "server": "cloudflare"},
            "__cfduid=xxx", "welcome to our site", 200,
        )
        assert waf == "cloudflare"

    def test_detect_modsecurity(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        waf = d._detect_waf(
            {"server": "Apache/2.4 (mod_security)"}, "", "not acceptable", 406,
        )
        assert waf == "modsecurity"

    def test_detect_imperva(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        waf = d._detect_waf(
            {"X-CDN": "Imperva"}, "incap_ses_123=abc", "access denied", 403,
        )
        assert waf == "imperva"

    def test_no_waf_returns_empty(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        waf = d._detect_waf({"server": "nginx"}, "", "hello world", 200)
        assert waf == ""

    def test_detect_cdn_cloudflare(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        assert d._detect_cdn({"cf-ray": "abc"}) == "cloudflare"

    def test_detect_anti_bot(self):
        from argus_lite.core.environment import EnvironmentDetector
        d = EnvironmentDetector()
        assert d._detect_anti_bot({}, "please solve captcha", "") is True
        assert d._detect_anti_bot({}, "normal page", "") is False


class TestEnvironmentProfileIntegration:
    def test_detect_returns_profile(self):
        from argus_lite.core.environment import EnvironmentDetector

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "nginx/1.24", "cf-ray": "abc123"}
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.__str__ = lambda s: ""
        mock_resp.text = "Hello World"

        mock_probe = MagicMock()
        mock_probe.status_code = 403
        mock_probe.headers = {"server": "cloudflare"}
        mock_probe.cookies = MagicMock()
        mock_probe.cookies.__str__ = lambda s: ""
        mock_probe.text = "blocked by cloudflare"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[mock_resp, mock_probe]):
            d = EnvironmentDetector()
            profile = asyncio.get_event_loop().run_until_complete(d.detect("example.com"))

        assert profile.cdn == "cloudflare"
        assert profile.waf_detected is True

    def test_detect_handles_errors(self):
        from argus_lite.core.environment import EnvironmentDetector

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("timeout")):
            d = EnvironmentDetector()
            profile = asyncio.get_event_loop().run_until_complete(d.detect("unreachable.com"))

        assert profile.waf_detected is False
