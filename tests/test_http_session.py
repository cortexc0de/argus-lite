"""TDD: Tests for HTTP Session Manager + Proxy Layer + ZAP integration."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestHttpSessionManager:
    def test_creation(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager(base_url="https://example.com")
        assert not session.is_authenticated
        assert session.get_cookies() == {}

    def test_set_auth_token(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager()
        session.set_auth_token("abc123", "Bearer")
        assert session._extra_headers["Authorization"] == "Bearer abc123"

    def test_set_custom_header(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager()
        session.set_header("X-Custom", "value")
        assert session._extra_headers["X-Custom"] == "value"

    def test_has_session_false_initially(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager()
        assert not session.has_session()

    def test_login_success(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager()
        mock_resp = MagicMock()
        mock_resp.status_code = 302

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                session.login("https://example.com/login", {"user": "admin", "pass": "test"})
            )
        assert result is True
        assert session.is_authenticated

    def test_login_failure(self):
        from argus_lite.core.http_session import HttpSessionManager

        session = HttpSessionManager()
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                session.login("https://example.com/login", {"user": "admin", "pass": "wrong"})
            )
        assert result is False
        assert not session.is_authenticated


class TestProxyLayer:
    def test_creation(self):
        from argus_lite.core.proxy import ProxyLayer

        proxy = ProxyLayer()
        assert not proxy.is_running
        assert proxy.request_count == 0

    def test_record_request(self):
        from argus_lite.core.proxy import ProxyLayer, RequestResponse

        proxy = ProxyLayer()
        rr = RequestResponse(
            id="1", method="GET", url="https://example.com/api",
            response_code=200,
        )
        proxy.record(rr)
        assert proxy.request_count == 1
        assert proxy.get_history()[0].url == "https://example.com/api"

    def test_filter_by_pattern(self):
        from argus_lite.core.proxy import ProxyLayer, RequestResponse

        proxy = ProxyLayer()
        proxy.record(RequestResponse(id="1", url="https://example.com/api/users"))
        proxy.record(RequestResponse(id="2", url="https://example.com/static/style.css"))
        proxy.record(RequestResponse(id="3", url="https://example.com/api/admin"))

        api_requests = proxy.get_by_pattern("/api/")
        assert len(api_requests) == 2

    def test_on_response_hook(self):
        from argus_lite.core.proxy import ProxyLayer, RequestResponse

        proxy = ProxyLayer()
        captured = []
        proxy.on_response(lambda rr: captured.append(rr.url))

        proxy.record(RequestResponse(id="1", url="https://test.com"))
        assert captured == ["https://test.com"]

    def test_proxy_url(self):
        from argus_lite.core.proxy import ProxyLayer

        proxy = ProxyLayer()
        assert proxy.get_proxy_url() == "http://127.0.0.1:8080"

    def test_is_available_check(self):
        from argus_lite.core.proxy import ProxyLayer

        # mitmproxy may or may not be installed
        result = ProxyLayer.is_available()
        assert isinstance(result, bool)


class TestZapScan:
    def test_alert_to_finding(self):
        from argus_lite.modules.analysis.zap_scan import _alert_to_finding

        alert = {
            "pluginId": "10016",
            "alertRef": "10016-1",
            "name": "Web Browser XSS Protection Not Enabled",
            "risk": "1",
            "description": "X-XSS-Protection header not set",
            "url": "https://example.com",
            "evidence": "missing header",
            "solution": "Set X-XSS-Protection header",
        }
        f = _alert_to_finding(alert)
        assert f.severity == "LOW"
        assert f.source == "zap"
        assert "XSS Protection" in f.title

    def test_alert_high_risk(self):
        from argus_lite.modules.analysis.zap_scan import _alert_to_finding

        alert = {
            "pluginId": "40012",
            "alertRef": "40012-1",
            "name": "Cross Site Scripting (Reflected)",
            "risk": "3",
            "description": "Reflected XSS found",
            "url": "https://example.com/search?q=test",
            "evidence": "<script>alert(1)</script>",
            "solution": "Sanitize input",
        }
        f = _alert_to_finding(alert)
        assert f.severity == "HIGH"
        assert f.type == "zap"

    def test_alert_unknown_risk_defaults_info(self):
        from argus_lite.modules.analysis.zap_scan import _alert_to_finding

        alert = {"pluginId": "99999", "name": "Custom", "risk": "99"}
        f = _alert_to_finding(alert)
        assert f.severity == "INFO"
