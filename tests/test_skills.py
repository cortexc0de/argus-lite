"""TDD: Tests for Skill System."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AppConfig


@pytest.fixture
def config():
    return AppConfig()


@pytest.fixture
def registry(config):
    from argus_lite.core.skills import build_skill_registry
    return build_skill_registry(config)


class TestSkillRegistry:
    def test_build_registry_has_11_skills(self, registry):
        assert len(registry._skills) == 14

    def test_get_existing_skill(self, registry):
        skill = registry.get("check_headers")
        assert skill is not None
        assert skill.name == "check_headers"

    def test_get_missing_skill(self, registry):
        assert registry.get("nonexistent") is None

    def test_list_available_includes_check_headers(self, registry):
        # check_headers has no tool dependency, always available
        names = [s.name for s in registry.list_available()]
        assert "check_headers" in names
        assert "test_payload" in names

    def test_to_llm_description(self, registry):
        desc = registry.to_llm_description()
        assert "check_headers" in desc
        assert "test_payload" in desc

    def test_execute_unknown_skill(self, registry):
        from argus_lite.core.agent_context import AgentContext
        ctx = AgentContext(target="example.com")
        result = asyncio.get_event_loop().run_until_complete(
            registry.execute("nonexistent_skill", {}, ctx)
        )
        assert not result.success
        assert "Unknown skill" in result.error


class TestCheckHeadersSkill:
    def test_execute_analyzes_headers(self):
        import httpx as _httpx
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import CheckHeadersSkill

        skill = CheckHeadersSkill()
        ctx = AgentContext(target="example.com")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.http_version = "1.1"
        mock_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}

        with patch("httpx.AsyncClient.head", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({}, ctx)
            )
        assert result.success
        assert "missing" in result.data


class TestTestPayloadSkill:
    def test_sends_get_request(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import TestPayloadSkill

        skill = TestPayloadSkill()
        ctx = AgentContext(target="example.com")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Hello World"
        mock_resp.content = b"Hello World"
        mock_resp.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"url": "https://example.com", "method": "GET"}, ctx)
            )
        assert result.success
        assert result.data["status_code"] == 200

    def test_detects_reflection(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import TestPayloadSkill

        skill = TestPayloadSkill()
        ctx = AgentContext(target="example.com")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html>Your search: <script>alert(1)</script></html>'
        mock_resp.content = mock_resp.text.encode()
        mock_resp.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({
                    "url": "https://example.com/search",
                    "param": "q",
                    "payload": "<script>alert(1)</script>",
                }, ctx)
            )
        assert result.success
        assert result.data["reflected"] is True


class TestSkillInstantiation:
    def test_all_skills_have_name_and_description(self, registry):
        for skill in registry._skills.values():
            assert skill.name
            assert skill.description
            assert len(skill.description) > 5
