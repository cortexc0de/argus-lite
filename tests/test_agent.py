"""TDD: Tests for AI Agent — LLM-driven pentesting orchestration."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AIConfig


@pytest.fixture
def ai_config():
    return AIConfig(enabled=True, api_key="test-key", model="test-model")


@pytest.fixture
def agent(ai_config):
    from argus_lite.core.agent import PentestAgent
    return PentestAgent(ai_config)


def _mock_llm_response(content: dict):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": json.dumps(content)}}]
    }
    return mock_resp


class TestClassifyEndpoints:
    def test_classifies_urls(self, agent):
        expected = {
            "endpoints": [
                {"url": "/api/user?id=123", "type": "api", "vulns_to_test": ["IDOR"],
                 "priority": "high", "params_at_risk": ["id"], "reason": "IDOR candidate"},
            ],
            "attack_strategy": "Focus on IDOR",
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.classify_endpoints(["/api/user?id=123"], ["Laravel"])
            )
        assert "endpoints" in result
        assert result["endpoints"][0]["vulns_to_test"] == ["IDOR"]

    def test_handles_empty_urls(self, agent):
        expected = {"endpoints": [], "attack_strategy": "No endpoints to analyze"}
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.classify_endpoints([], [])
            )
        assert result["endpoints"] == []


class TestGeneratePayloads:
    def test_generates_context_payloads(self, agent):
        expected = {
            "payloads": [
                {"payload": "' OR 1=1--", "technique": "classic OR",
                 "bypass": "none", "confidence": "high"},
            ]
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.generate_payloads(
                    url="/api/user?id=1", vuln_type="SQLi",
                    tech_stack=["MySQL", "PHP"], param="id",
                )
            )
        assert len(result["payloads"]) == 1
        assert result["payloads"][0]["confidence"] == "high"


class TestDecideNextAction:
    def test_decides_action(self, agent):
        from datetime import datetime, timezone
        from argus_lite.models.scan import ScanResult

        scan = ScanResult(
            scan_id="test", target="example.com", target_type="domain",
            status="completed", started_at=datetime.now(tz=timezone.utc),
        )
        expected = {
            "thought": "Target has no recon data yet, starting with subdomains",
            "action": "enumerate_subdomains",
            "input": {"target": "example.com"},
            "priority_targets": [],
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.decide_next_action(scan)
            )
        assert result["action"] == "enumerate_subdomains"

    def test_done_action(self, agent):
        from datetime import datetime, timezone
        from argus_lite.models.scan import ScanResult

        scan = ScanResult(
            scan_id="test", target="example.com", target_type="domain",
            status="completed", started_at=datetime.now(tz=timezone.utc),
        )
        expected = {
            "thought": "All checks complete",
            "action": "done",
            "input": {},
            "report": "No critical vulnerabilities found",
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.decide_next_action(scan)
            )
        assert result["action"] == "done"


class TestAgentMemory:
    def test_records_steps(self, agent):
        agent.record_step({"action": "scan_nuclei"}, "found 3 vulns")
        agent.record_step({"action": "scan_xss"}, "found 1 xss")
        assert len(agent._history) == 2
        assert agent._history[0]["decision"]["action"] == "scan_nuclei"

    def test_no_key_returns_error(self):
        from argus_lite.core.agent import PentestAgent

        agent = PentestAgent(AIConfig(api_key=""))
        result = asyncio.get_event_loop().run_until_complete(
            agent.classify_endpoints(["/test"], [])
        )
        assert "error" in result


class TestAnalyzeResponse:
    def test_analyzes_http_response(self, agent):
        expected = {
            "issues": [{"type": "info_disclosure", "description": "Server header leaks version",
                        "severity": "low"}],
            "recommendations": ["Remove Server header"],
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_mock_llm_response(expected)):
            result = asyncio.get_event_loop().run_until_complete(
                agent.analyze_response("/api/test", {"status_code": 200, "headers": {"Server": "Apache/2.4.51"}})
            )
        assert len(result["issues"]) == 1
