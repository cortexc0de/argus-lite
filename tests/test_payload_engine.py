"""TDD: Tests for Adaptive Payload Engine."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AIConfig


class TestPayloadAttempt:
    def test_attempt_model(self):
        from argus_lite.core.payload_engine import PayloadAttempt
        a = PayloadAttempt(payload="' OR 1=1--", response_code=200, reflected=False, blocked=False)
        assert a.payload == "' OR 1=1--"


class TestPayloadEngine:
    def test_adaptive_test_stops_on_reflection(self):
        from argus_lite.core.payload_engine import PayloadEngine

        config = AIConfig(api_key="test", model="test")
        engine = PayloadEngine(config, max_iterations=3)

        # Mock LLM to return payload
        async def mock_llm(*args, **kwargs):
            return {"payload": "<script>alert(1)</script>"}

        # Mock HTTP to show reflection
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'Result: <script>alert(1)</script>'
        mock_resp.content = mock_resp.text.encode()
        mock_resp.headers = {}

        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, side_effect=mock_llm), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            attempts = asyncio.get_event_loop().run_until_complete(
                engine.adaptive_test("https://example.com/search", "q", "XSS")
            )

        assert len(attempts) == 1  # stopped after first success
        assert attempts[0].reflected is True

    def test_adaptive_test_retries_on_block(self):
        from argus_lite.core.payload_engine import PayloadEngine

        config = AIConfig(api_key="test", model="test")
        engine = PayloadEngine(config, max_iterations=2)

        async def mock_llm(*args, **kwargs):
            return {"payload": "test_payload"}

        mock_blocked = MagicMock()
        mock_blocked.status_code = 403
        mock_blocked.text = "Blocked by WAF"
        mock_blocked.content = b"Blocked by WAF"
        mock_blocked.headers = {}

        mock_ok = MagicMock()
        mock_ok.status_code = 200
        mock_ok.text = "test_payload reflected"
        mock_ok.content = mock_ok.text.encode()
        mock_ok.headers = {}

        call_count = [0]

        async def mock_get(*args, **kwargs):
            call_count[0] += 1
            return mock_blocked if call_count[0] == 1 else mock_ok

        with patch("argus_lite.core.agent._call_llm", new_callable=AsyncMock, side_effect=mock_llm), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            attempts = asyncio.get_event_loop().run_until_complete(
                engine.adaptive_test("https://example.com", "q", "XSS")
            )

        assert len(attempts) == 2
        assert attempts[0].blocked is True
        assert attempts[1].reflected is True

    def test_no_api_key_returns_empty(self):
        from argus_lite.core.payload_engine import PayloadEngine

        config = AIConfig(api_key="", model="test")
        engine = PayloadEngine(config)
        attempts = asyncio.get_event_loop().run_until_complete(
            engine.adaptive_test("https://x.com", "q", "XSS")
        )
        assert attempts == []
