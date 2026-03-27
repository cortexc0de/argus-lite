"""Attack Trace — full observability of agent decisions and actions.

Every agent decision, skill execution, and adaptation is recorded as a
TraceEvent. The AttackTrace can be saved as JSON for post-analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TraceEvent:
    """A single event in the attack trace."""

    agent: str = "main"
    action: str = ""            # "decide", "execute", "adapt", "done"
    skill: str = ""
    thought: str = ""           # LLM reasoning
    result: str = ""
    findings_count: int = 0
    duration_ms: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


class AttackTrace:
    """Ordered log of all agent events for a single run."""

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def add(self, event: TraceEvent) -> None:
        self.events.append(event)

    def to_json(self) -> str:
        """Serialize trace to JSON string."""
        return json.dumps({
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "agent": e.agent,
                    "action": e.action,
                    "skill": e.skill,
                    "thought": e.thought,
                    "result": e.result,
                    "findings_count": e.findings_count,
                    "duration_ms": e.duration_ms,
                }
                for e in self.events
            ]
        }, ensure_ascii=False)

    def to_timeline(self) -> str:
        """Render human-readable timeline."""
        if not self.events:
            return ""
        lines: list[str] = []
        for i, e in enumerate(self.events):
            ts = e.timestamp.strftime("%H:%M:%S")
            status = f"[{e.findings_count}F]" if e.findings_count else ""
            dur = f" ({e.duration_ms}ms)" if e.duration_ms else ""
            lines.append(f"  {ts} [{e.agent}] {e.action}: {e.skill} {status}{dur}")
            if e.thought:
                lines.append(f"         > {e.thought[:120]}")
            if e.result:
                lines.append(f"         = {e.result[:120]}")
        return "\n".join(lines)

    def save(self, path: Path) -> None:
        """Save trace to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
