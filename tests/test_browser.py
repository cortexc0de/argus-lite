"""TDD: Tests for Browser Agent, GraphQL, and WebSocket skills."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus_lite.core.config import AppConfig


class TestBrowserAgent:
    def test_creation(self):
        from argus_lite.core.browser import BrowserAgent

        agent = BrowserAgent()
        assert not agent.is_running
        assert agent.get_api_calls() == []
        assert agent.get_websocket_messages() == []

    def test_is_available_check(self):
        from argus_lite.core.browser import BrowserAgent

        result = BrowserAgent.is_available()
        assert isinstance(result, bool)

    def test_captured_request_dataclass(self):
        from argus_lite.core.browser import CapturedRequest

        req = CapturedRequest(method="POST", url="https://api.test.com/data")
        assert req.method == "POST"
        assert req.resource_type == ""

    def test_captured_websocket_dataclass(self):
        from argus_lite.core.browser import CapturedWebSocket

        ws = CapturedWebSocket(url="wss://test.com/ws", direction="sent", payload="ping")
        assert ws.direction == "sent"


class TestBrowseTargetSkill:
    def test_skill_attributes(self):
        from argus_lite.core.skills import BrowseTargetSkill

        skill = BrowseTargetSkill()
        assert skill.name == "browse_target"
        assert "browser" in skill.description.lower()


class TestGraphQLIntrospectSkill:
    def test_skill_attributes(self):
        from argus_lite.core.skills import GraphQLIntrospectSkill

        skill = GraphQLIntrospectSkill()
        assert skill.name == "graphql_introspect"
        assert "graphql" in skill.description.lower()

    def test_introspection_success(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import GraphQLIntrospectSkill

        skill = GraphQLIntrospectSkill()
        ctx = AgentContext(target="example.com")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "User", "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "email", "type": {"name": "String"}},
                        ]},
                        {"name": "Query", "fields": [
                            {"name": "user", "type": {"name": "User"}},
                        ]},
                        {"name": "__Schema", "fields": []},
                    ],
                    "queryType": {"name": "Query"},
                    "mutationType": None,
                }
            }
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"endpoint": "https://example.com/graphql"}, ctx)
            )

        assert result.success
        assert result.data["types_count"] == 2  # User + Query (not __Schema)
        assert "User.id" in result.data["idor_candidates"]

    def test_introspection_disabled(self):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skills import GraphQLIntrospectSkill

        skill = GraphQLIntrospectSkill()
        ctx = AgentContext(target="example.com")

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "errors": [{"message": "Introspection is not allowed"}]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            result = asyncio.get_event_loop().run_until_complete(
                skill.execute({"endpoint": "https://example.com/graphql"}, ctx)
            )

        assert not result.success
        assert "disabled" in result.error.lower() or "not allowed" in result.error.lower()


class TestWebSocketSkill:
    def test_skill_attributes(self):
        from argus_lite.core.skills import TestWebSocketSkill

        skill = TestWebSocketSkill()
        assert skill.name == "test_websocket"
        assert "websocket" in skill.description.lower()


class TestSkillRegistryWithNewSkills:
    def test_registry_has_14_skills(self):
        from argus_lite.core.skills import build_skill_registry

        registry = build_skill_registry(AppConfig())
        assert len(registry._skills) == 14  # 11 original + browse + graphql + websocket

    def test_new_skills_registered(self):
        from argus_lite.core.skills import build_skill_registry

        registry = build_skill_registry(AppConfig())
        assert registry.get("browse_target") is not None
        assert registry.get("graphql_introspect") is not None
        assert registry.get("test_websocket") is not None

    def test_all_skills_have_name_and_description(self):
        from argus_lite.core.skills import build_skill_registry

        registry = build_skill_registry(AppConfig())
        for skill in registry._skills.values():
            assert skill.name, f"Skill missing name: {skill}"
            assert skill.description, f"Skill missing description: {skill.name}"
