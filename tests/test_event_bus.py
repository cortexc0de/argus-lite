"""TDD: Tests for Agent Event Bus and Executable Playbooks."""

from __future__ import annotations

import asyncio

import pytest


class TestEvent:
    def test_create_event(self):
        from argus_lite.core.event_bus import Event

        event = Event(type="finding.new", source="recon", data={"title": "XSS found"})
        assert event.type == "finding.new"
        assert event.source == "recon"
        assert event.timestamp is not None

    def test_event_default_source(self):
        from argus_lite.core.event_bus import Event

        event = Event(type="test")
        assert event.source == "main"


class TestAgentEventBus:
    def test_publish_and_subscribe(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        received = []
        bus.subscribe("finding.new", lambda e: received.append(e))

        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="finding.new", data={"title": "XSS"}))
        )
        assert len(received) == 1
        assert received[0].data["title"] == "XSS"

    def test_subscribe_multiple_callbacks(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        results = {"a": 0, "b": 0}
        bus.subscribe("tech.detected", lambda e: results.update(a=results["a"] + 1))
        bus.subscribe("tech.detected", lambda e: results.update(b=results["b"] + 1))

        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="tech.detected"))
        )
        assert results["a"] == 1
        assert results["b"] == 1

    def test_unsubscribe(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        received = []
        cb = lambda e: received.append(e)
        bus.subscribe("test", cb)
        bus.unsubscribe("test", cb)

        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="test"))
        )
        assert len(received) == 0

    def test_event_history(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        asyncio.get_event_loop().run_until_complete(bus.publish(Event(type="a")))
        asyncio.get_event_loop().run_until_complete(bus.publish(Event(type="b")))
        asyncio.get_event_loop().run_until_complete(bus.publish(Event(type="a")))

        assert bus.event_count == 3
        assert len(bus.get_history("a")) == 2
        assert len(bus.get_history("b")) == 1

    def test_async_callback(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        received = []

        async def async_handler(event):
            received.append(event.type)

        bus.subscribe("async.test", async_handler)
        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="async.test"))
        )
        assert received == ["async.test"]

    def test_callback_error_doesnt_crash(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        bus.subscribe("bad", lambda e: 1 / 0)  # ZeroDivisionError
        bus.subscribe("bad", lambda e: None)    # should still run

        # Should not raise
        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="bad"))
        )
        assert bus.event_count == 1

    def test_no_subscribers_no_error(self):
        from argus_lite.core.event_bus import AgentEventBus, Event

        bus = AgentEventBus()
        asyncio.get_event_loop().run_until_complete(
            bus.publish(Event(type="orphan"))
        )
        assert bus.event_count == 1


class TestPlaybook:
    def test_playbook_creation(self):
        from argus_lite.core.knowledge_base import Playbook, PlaybookStep

        pb = Playbook(
            name="test_playbook",
            tech_match=["WordPress"],
            steps=[
                PlaybookStep(skill="scan_nuclei", params={"tags": "wordpress"}),
                PlaybookStep(skill="check_headers"),
            ],
        )
        assert len(pb.steps) == 2
        assert pb.steps[0].skill == "scan_nuclei"

    def test_playbook_matches_tech(self):
        from argus_lite.core.knowledge_base import Playbook

        pb = Playbook(name="wp", tech_match=["WordPress"], steps=[])
        assert pb.matches_tech(["WordPress", "PHP", "nginx"])
        assert pb.matches_tech(["wordpress"])  # case-insensitive
        assert not pb.matches_tech(["Laravel", "PHP"])

    def test_get_playbooks_for_tech(self):
        from argus_lite.core.knowledge_base import get_playbooks_for_tech

        playbooks = get_playbooks_for_tech(["WordPress"])
        assert len(playbooks) >= 1
        assert any(p.name == "wordpress_csrf_chain" for p in playbooks)

    def test_get_playbooks_for_graphql(self):
        from argus_lite.core.knowledge_base import get_playbooks_for_tech

        playbooks = get_playbooks_for_tech(["GraphQL"])
        assert len(playbooks) >= 1
        assert any(p.name == "graphql_idor_chain" for p in playbooks)

    def test_get_playbooks_for_unknown_tech(self):
        from argus_lite.core.knowledge_base import get_playbooks_for_tech

        playbooks = get_playbooks_for_tech(["CustomFramework"])
        assert playbooks == []

    def test_builtin_playbooks_count(self):
        from argus_lite.core.knowledge_base import BUILTIN_PLAYBOOKS

        assert len(BUILTIN_PLAYBOOKS) == 4

    def test_playbook_step_defaults(self):
        from argus_lite.core.knowledge_base import PlaybookStep

        step = PlaybookStep(skill="check_headers")
        assert step.params == {}
        assert step.condition == ""
        assert step.on_fail == "continue"
