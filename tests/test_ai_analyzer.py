"""TDD: Tests for AI analyzer — all API calls mocked."""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AIConfig
from argus_lite.models.ai import AIAnalysis
from argus_lite.models.scan import ScanResult


def _scan() -> ScanResult:
    from argus_lite.models.finding import Finding
    from argus_lite.models.analysis import AnalysisResult, SecurityHeadersResult, Technology
    from argus_lite.models.recon import ReconResult, Subdomain

    return ScanResult(
        scan_id="test", target="example.com", target_type="domain",
        status="completed", started_at=datetime.now(tz=timezone.utc),
        recon=ReconResult(subdomains=[Subdomain(name="www.example.com", source="subfinder")]),
        analysis=AnalysisResult(
            technologies=[Technology(name="WordPress", version="6.4.2")],
            security_headers=SecurityHeadersResult(missing_headers=["hsts", "csp"]),
        ),
        findings=[Finding(
            id="f1", type="missing_header", severity="INFO", title="Missing HSTS",
            description="HSTS not set", asset="example.com", evidence="header not found",
            source="security_headers", remediation="Add HSTS header",
        )],
    )


def _ai_response_json() -> str:
    """Mock AI response matching AIAnalysis schema."""
    return json.dumps({
        "executive_summary": "The target has moderate security posture with missing headers.",
        "attack_chains": [
            {"name": "Header exploitation", "steps": ["No HSTS", "MITM possible"], "severity": "MEDIUM", "likelihood": "LOW"}
        ],
        "prioritized_findings": [
            {"original_id": "f1", "new_priority": 1, "reason": "Easy to fix", "exploitability": "EASY"}
        ],
        "recommendations": ["Add HSTS header", "Add CSP header", "Update WordPress"],
        "trend_analysis": "",
    })


def _mock_openai_response(content: str, tokens: int = 500):
    """Create a mock httpx response matching OpenAI chat/completions format."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "choices": [{"message": {"content": content}}],
        "usage": {"total_tokens": tokens},
    }
    return resp


class TestAIAnalyzer:
    def test_builds_prompt_with_target_info(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key="test"))
        prompt = analyzer._build_user_prompt(_scan())
        assert "example.com" in prompt
        assert "WordPress" in prompt
        assert "Missing HSTS" in prompt

    def test_calls_correct_endpoint(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        config = AIConfig(api_key="sk-test", base_url="http://localhost:1234/v1", model="local-model")
        analyzer = AIAnalyzer(config)

        mock_resp = _mock_openai_response(_ai_response_json())

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))
            call_args = mock_post.call_args
            assert "http://localhost:1234/v1/chat/completions" in str(call_args)

    def test_parses_json_response(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key="test"))
        mock_resp = _mock_openai_response(_ai_response_json(), tokens=1500)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))

        assert "moderate" in result.executive_summary.lower()
        assert len(result.attack_chains) == 1
        assert len(result.recommendations) == 3
        assert result.tokens_used == 1500

    def test_graceful_on_api_error(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key="test"))
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))

        assert isinstance(result, AIAnalysis)
        assert result.executive_summary == ""

    def test_graceful_on_invalid_json(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key="test"))
        mock_resp = _mock_openai_response("This is not JSON at all")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))

        assert isinstance(result, AIAnalysis)

    def test_graceful_on_timeout(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer
        import httpx

        analyzer = AIAnalyzer(AIConfig(api_key="test", timeout=1))

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))

        assert isinstance(result, AIAnalysis)
        assert result.executive_summary == ""

    def test_no_api_key_returns_empty(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key=""))
        result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))
        assert result.executive_summary == ""

    def test_model_name_recorded(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        config = AIConfig(api_key="test", model="my-custom-model")
        analyzer = AIAnalyzer(config)
        mock_resp = _mock_openai_response(_ai_response_json())

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(analyzer.analyze(_scan()))

        assert result.model_used == "my-custom-model"

    def test_trend_with_previous_scan(self):
        from argus_lite.core.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(AIConfig(api_key="test"))
        prev = _scan()
        curr = _scan()

        prompt = analyzer._build_user_prompt(curr, previous_scan=prev)
        assert "previous" in prompt.lower() or "trend" in prompt.lower() or "comparison" in prompt.lower()
