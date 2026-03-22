import logging
from datetime import datetime, timezone
from typing import Any, Callable

from argus_lite.core.config import AppConfig
from argus_lite.core.pipeline import PipelineDefinition
from argus_lite.core.tool_runner import BaseToolRunner
from argus_lite.models.scan import StageError

logger = logging.getLogger(__name__)


class PipelineContext:
    """Shared data bag for pipeline stages."""

    def __init__(self, target: str, config: AppConfig):
        self.target = target
        self.config = config
        self.results: dict[str, Any] = {}
        self.tools_used: list[str] = []
        self.errors: list[StageError] = []
        self.completed_stages: list[str] = []
        self.skipped_stages: list[str] = []
        self.shutdown_requested: bool = False


# Tool name -> async function mapping
# Will be populated with actual tool functions
TOOL_DISPATCH: dict[str, Callable] = {}


def register_tool(name: str):
    """Decorator to register a tool function."""
    def decorator(func):
        TOOL_DISPATCH[name] = func
        return func
    return decorator


class PipelineEngine:
    def __init__(self, definition: PipelineDefinition, config: AppConfig,
                 on_progress: Callable[[str, str], None] | None = None,
                 plugins: dict | None = None):
        self.definition = definition
        self.config = config
        self._on_progress = on_progress or (lambda s, st: None)
        self._plugins = plugins or {}

    async def execute(self, context: PipelineContext) -> None:
        for stage in self.definition.stages:
            if context.shutdown_requested:
                context.skipped_stages.append(stage.name)
                self._on_progress(stage.name, "skip")
                continue

            self._on_progress(stage.name, "start")
            try:
                for tool_name in stage.tools:
                    if context.shutdown_requested:
                        break
                    await self._run_tool(tool_name, context)
                context.completed_stages.append(stage.name)
                self._on_progress(stage.name, "done")
            except Exception as e:
                context.errors.append(StageError(
                    stage=stage.name, error_type=type(e).__name__,
                    message=str(e), timestamp=datetime.now(tz=timezone.utc),
                ))
                self._on_progress(stage.name, "fail")

    async def _run_tool(self, name: str, context: PipelineContext) -> None:
        # Check builtin dispatch first
        if name in TOOL_DISPATCH:
            try:
                await TOOL_DISPATCH[name](context)
                context.tools_used.append(name)
            except Exception as e:
                logger.warning("Tool '%s' failed: %s", name, e)
            return

        # Check plugins
        if name in self._plugins:
            plugin = self._plugins[name]
            if plugin.check_available():
                try:
                    await plugin.run(context.results, context.config)
                    context.tools_used.append(name)
                except Exception as e:
                    logger.warning("Plugin '%s' failed: %s", name, e)
            return

        logger.warning("Tool '%s' not found in dispatch or plugins", name)
