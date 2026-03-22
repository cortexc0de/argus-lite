"""Tests for pipeline definition, loading, context, and engine."""

from __future__ import annotations

import asyncio
import textwrap
from unittest.mock import AsyncMock, MagicMock

import pytest

from argus_lite.core.config import AppConfig
from argus_lite.core.pipeline import PipelineDefinition, PipelineStage, load_pipeline
from argus_lite.core.pipeline_engine import (
    TOOL_DISPATCH,
    PipelineContext,
    PipelineEngine,
    register_tool,
)


# ---------------------------------------------------------------------------
# test_load_pipeline_from_yaml
# ---------------------------------------------------------------------------

def test_load_pipeline_from_yaml(tmp_path):
    """Load default.yaml and verify stages are parsed correctly."""
    yaml_file = tmp_path / "pipeline.yaml"
    yaml_file.write_text(textwrap.dedent("""\
        stages:
          - name: recon
            tools: [subfinder, dnsx]
          - name: analysis
            tools: [nuclei]
          - name: report
            auto: true
    """))

    pipeline = load_pipeline(yaml_file)

    assert len(pipeline.stages) == 3
    assert pipeline.stages[0].name == "recon"
    assert pipeline.stages[0].tools == ["subfinder", "dnsx"]
    assert pipeline.stages[2].name == "report"
    assert pipeline.stages[2].auto is True


# ---------------------------------------------------------------------------
# test_pipeline_stage_model
# ---------------------------------------------------------------------------

def test_pipeline_stage_model():
    """Create PipelineStage with tools and verify fields."""
    stage = PipelineStage(name="recon", tools=["dig", "whois"])

    assert stage.name == "recon"
    assert stage.tools == ["dig", "whois"]
    assert stage.auto is False


# ---------------------------------------------------------------------------
# test_pipeline_context
# ---------------------------------------------------------------------------

def test_pipeline_context():
    """Create context, add results, verify attributes."""
    config = AppConfig()
    ctx = PipelineContext(target="example.com", config=config)

    assert ctx.target == "example.com"
    assert ctx.results == {}
    assert ctx.tools_used == []
    assert ctx.errors == []
    assert ctx.completed_stages == []
    assert ctx.skipped_stages == []
    assert ctx.shutdown_requested is False

    ctx.results["dns"] = {"records": ["1.2.3.4"]}
    assert "dns" in ctx.results


# ---------------------------------------------------------------------------
# test_engine_executes_stages
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_executes_stages():
    """Mock tools, verify stage progression through the engine."""
    # Save and restore TOOL_DISPATCH to avoid side effects
    saved = dict(TOOL_DISPATCH)
    TOOL_DISPATCH.clear()

    try:
        call_order = []

        async def mock_tool_a(ctx):
            call_order.append("tool_a")

        async def mock_tool_b(ctx):
            call_order.append("tool_b")

        TOOL_DISPATCH["tool_a"] = mock_tool_a
        TOOL_DISPATCH["tool_b"] = mock_tool_b

        definition = PipelineDefinition(stages=[
            PipelineStage(name="stage1", tools=["tool_a"]),
            PipelineStage(name="stage2", tools=["tool_b"]),
        ])

        config = AppConfig()
        progress_log = []
        engine = PipelineEngine(
            definition=definition,
            config=config,
            on_progress=lambda s, st: progress_log.append((s, st)),
        )

        ctx = PipelineContext(target="example.com", config=config)
        await engine.execute(ctx)

        assert call_order == ["tool_a", "tool_b"]
        assert ctx.completed_stages == ["stage1", "stage2"]
        assert ctx.tools_used == ["tool_a", "tool_b"]
        assert ("stage1", "start") in progress_log
        assert ("stage1", "done") in progress_log
        assert ("stage2", "start") in progress_log
        assert ("stage2", "done") in progress_log
    finally:
        TOOL_DISPATCH.clear()
        TOOL_DISPATCH.update(saved)


# ---------------------------------------------------------------------------
# test_engine_shutdown_skips_remaining
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_shutdown_skips_remaining():
    """Set shutdown flag, check that remaining stages are skipped."""
    saved = dict(TOOL_DISPATCH)
    TOOL_DISPATCH.clear()

    try:
        async def shutdown_tool(ctx):
            ctx.shutdown_requested = True

        TOOL_DISPATCH["shutdown_trigger"] = shutdown_tool

        definition = PipelineDefinition(stages=[
            PipelineStage(name="stage1", tools=["shutdown_trigger"]),
            PipelineStage(name="stage2", tools=["some_tool"]),
        ])

        config = AppConfig()
        ctx = PipelineContext(target="example.com", config=config)

        engine = PipelineEngine(definition=definition, config=config)
        await engine.execute(ctx)

        assert "stage1" in ctx.completed_stages
        assert "stage2" in ctx.skipped_stages
    finally:
        TOOL_DISPATCH.clear()
        TOOL_DISPATCH.update(saved)


# ---------------------------------------------------------------------------
# test_engine_tool_failure_non_fatal
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_tool_failure_non_fatal():
    """A tool that raises still allows the stage to complete (tool failure is caught in _run_tool)."""
    saved = dict(TOOL_DISPATCH)
    TOOL_DISPATCH.clear()

    try:
        async def failing_tool(ctx):
            raise RuntimeError("boom")

        async def ok_tool(ctx):
            pass

        TOOL_DISPATCH["failing"] = failing_tool
        TOOL_DISPATCH["ok"] = ok_tool

        definition = PipelineDefinition(stages=[
            PipelineStage(name="stage1", tools=["failing", "ok"]),
        ])

        config = AppConfig()
        ctx = PipelineContext(target="example.com", config=config)

        engine = PipelineEngine(definition=definition, config=config)
        await engine.execute(ctx)

        # Stage completes because _run_tool catches exceptions for dispatch tools
        assert "stage1" in ctx.completed_stages
        # Only ok_tool succeeded
        assert "ok" in ctx.tools_used
        assert "failing" not in ctx.tools_used
    finally:
        TOOL_DISPATCH.clear()
        TOOL_DISPATCH.update(saved)


# ---------------------------------------------------------------------------
# test_register_tool_decorator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_tool_decorator():
    """register_tool decorator adds a function to TOOL_DISPATCH."""
    saved = dict(TOOL_DISPATCH)

    try:
        @register_tool("test_decorator_tool")
        async def my_tool(ctx):
            ctx.results["decorator_test"] = True

        assert "test_decorator_tool" in TOOL_DISPATCH

        # Verify it actually works when called
        config = AppConfig()
        ctx = PipelineContext(target="example.com", config=config)
        await TOOL_DISPATCH["test_decorator_tool"](ctx)
        assert ctx.results["decorator_test"] is True
    finally:
        TOOL_DISPATCH.clear()
        TOOL_DISPATCH.update(saved)
