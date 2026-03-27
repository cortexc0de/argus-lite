"""Agent Event Bus — pub/sub for multi-agent coordination.

Agents can publish events and subscribe to events from other agents,
enabling real-time coordination without direct coupling.

Events:
  "finding.new"    — when any agent discovers a finding
  "tech.detected"  — when technology stack is identified
  "goal.achieved"  — when a mission goal is completed
  "goal.failed"    — when a goal fails
  "scan.complete"  — when a scan phase finishes
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """A typed event with source agent and payload."""

    type: str
    source: str = "main"
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


# Callback type: can be sync or async
EventCallback = Callable[[Event], Any]


class AgentEventBus:
    """In-process pub/sub for agent coordination."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventCallback]] = {}
        self._history: list[Event] = []

    def subscribe(self, event_type: str, callback: EventCallback) -> None:
        """Register a callback for an event type. Supports both sync and async."""
        self._subscribers.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: str, callback: EventCallback) -> None:
        """Remove a callback."""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb is not callback
            ]

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers. Calls async callbacks with await."""
        self._history.append(event)
        callbacks = self._subscribers.get(event.type, [])
        for cb in callbacks:
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.warning("Event callback failed for '%s': %s", event.type, exc)

    def get_history(self, event_type: str | None = None) -> list[Event]:
        """Get event history, optionally filtered by type."""
        if event_type:
            return [e for e in self._history if e.type == event_type]
        return list(self._history)

    @property
    def event_count(self) -> int:
        return len(self._history)
