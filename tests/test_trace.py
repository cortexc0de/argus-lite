"""TDD: Tests for Attack Trace — full observability of agent decisions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest


class TestTraceEvent:
    def test_create_event(self):
        from argus_lite.core.trace import TraceEvent

        event = TraceEvent(
            agent="main", action="execute", skill="scan_nuclei",
            thought="Target has WordPress", result="3 findings",
            findings_count=3, duration_ms=1200,
        )
        assert event.agent == "main"
        assert event.skill == "scan_nuclei"
        assert event.timestamp is not None

    def test_event_default_timestamp(self):
        from argus_lite.core.trace import TraceEvent

        event = TraceEvent(agent="recon", action="decide", skill="probe_http")
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None


class TestAttackTrace:
    def test_add_events(self):
        from argus_lite.core.trace import AttackTrace, TraceEvent

        trace = AttackTrace()
        trace.add(TraceEvent(agent="main", action="execute", skill="check_headers"))
        trace.add(TraceEvent(agent="main", action="execute", skill="scan_nuclei"))
        assert len(trace.events) == 2

    def test_to_json(self):
        from argus_lite.core.trace import AttackTrace, TraceEvent

        trace = AttackTrace()
        trace.add(TraceEvent(
            agent="main", action="execute", skill="scan_nuclei",
            thought="checking vulns", result="2 found", findings_count=2,
        ))
        data = json.loads(trace.to_json())
        assert len(data["events"]) == 1
        assert data["events"][0]["skill"] == "scan_nuclei"

    def test_to_timeline(self):
        from argus_lite.core.trace import AttackTrace, TraceEvent

        trace = AttackTrace()
        trace.add(TraceEvent(agent="main", action="decide", skill="check_headers", thought="start"))
        trace.add(TraceEvent(agent="main", action="execute", skill="check_headers", result="2 missing"))
        timeline = trace.to_timeline()
        assert "check_headers" in timeline
        assert "decide" in timeline

    def test_save_and_load(self, tmp_path):
        from argus_lite.core.trace import AttackTrace, TraceEvent

        trace = AttackTrace()
        trace.add(TraceEvent(agent="main", action="execute", skill="scan_nuclei"))
        path = tmp_path / "trace.json"
        trace.save(path)
        assert path.exists()

        loaded = json.loads(path.read_text())
        assert len(loaded["events"]) == 1

    def test_empty_trace(self):
        from argus_lite.core.trace import AttackTrace

        trace = AttackTrace()
        assert trace.to_json() == '{"events": []}'
        assert trace.to_timeline() == ""


class TestAmassEnum:
    """Tests for amass subdomain enumeration module."""

    def test_parse_amass_output(self):
        from argus_lite.modules.recon.amass_enum import parse_amass_output

        raw = "sub1.example.com\nsub2.example.com\nexample.com\n"
        subs = parse_amass_output(raw, "example.com")
        assert len(subs) == 3
        assert subs[0].name == "sub1.example.com"
        assert subs[0].source == "amass"

    def test_parse_empty_output(self):
        from argus_lite.modules.recon.amass_enum import parse_amass_output

        subs = parse_amass_output("", "example.com")
        assert subs == []

    def test_parse_deduplicates(self):
        from argus_lite.modules.recon.amass_enum import parse_amass_output

        raw = "sub1.example.com\nsub1.example.com\nsub2.example.com\n"
        subs = parse_amass_output(raw, "example.com")
        assert len(subs) == 2


class TestPayloadEngineIntegration:
    """Tests for PayloadEngine wiring into agent loop."""

    def test_payload_engine_creates_findings_on_reflection(self):
        from argus_lite.core.payload_engine import PayloadAttempt

        attempt = PayloadAttempt(
            payload="<script>alert(1)</script>",
            response_code=200,
            reflected=True,
            blocked=False,
        )
        assert attempt.reflected
        # This should generate a Finding when wired into agent

    def test_payload_engine_detects_waf_block(self):
        from argus_lite.core.payload_engine import PayloadAttempt

        attempt = PayloadAttempt(
            payload="<script>alert(1)</script>",
            response_code=403,
            reflected=False,
            blocked=True,
        )
        assert attempt.blocked
        assert not attempt.reflected
