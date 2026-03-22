"""TDD: Tests for ToolRunner abstraction — written BEFORE implementation."""

import asyncio

import pytest


class TestToolOutput:
    def test_tool_output_fields(self):
        from argus_lite.core.tool_runner import ToolOutput

        out = ToolOutput(
            returncode=0,
            stdout="result",
            stderr="",
            duration_seconds=1.5,
            command=["echo", "hello"],
        )
        assert out.returncode == 0
        assert out.stdout == "result"
        assert out.command == ["echo", "hello"]

    def test_tool_output_success_property(self):
        from argus_lite.core.tool_runner import ToolOutput

        ok = ToolOutput(
            returncode=0, stdout="", stderr="", duration_seconds=0.1, command=["true"]
        )
        assert ok.success is True

        fail = ToolOutput(
            returncode=1, stdout="", stderr="err", duration_seconds=0.1, command=["false"]
        )
        assert fail.success is False


class TestBaseToolRunner:
    def test_check_available_existing_tool(self):
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner(name="echo", path="/usr/bin/echo")
        assert runner.check_available() is True

    def test_check_available_missing_tool(self):
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner(name="nonexistent", path="/usr/bin/nonexistent_tool_xyz")
        assert runner.check_available() is False

    def test_run_echo(self):
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner(name="echo", path="/usr/bin/echo")
        result = asyncio.get_event_loop().run_until_complete(
            runner.run(["hello", "world"])
        )
        assert result.returncode == 0
        assert "hello world" in result.stdout
        assert result.command == ["/usr/bin/echo", "hello", "world"]
        assert result.duration_seconds >= 0

    def test_run_timeout(self):
        from argus_lite.core.tool_runner import BaseToolRunner, ToolTimeoutError

        runner = BaseToolRunner(name="sleep", path="/usr/bin/sleep")
        with pytest.raises(ToolTimeoutError):
            asyncio.get_event_loop().run_until_complete(
                runner.run(["10"], timeout=1)
            )

    def test_run_nonexistent_tool_raises(self):
        from argus_lite.core.tool_runner import BaseToolRunner, ToolNotFoundError

        runner = BaseToolRunner(
            name="nonexistent", path="/usr/bin/nonexistent_tool_xyz"
        )
        with pytest.raises(ToolNotFoundError):
            asyncio.get_event_loop().run_until_complete(runner.run([]))

    def test_never_uses_shell(self):
        """Ensure the runner does NOT interpret shell metacharacters."""
        from argus_lite.core.tool_runner import BaseToolRunner

        runner = BaseToolRunner(name="echo", path="/usr/bin/echo")
        result = asyncio.get_event_loop().run_until_complete(
            runner.run(["hello; echo INJECTED"])
        )
        # Shell would split this; subprocess list won't
        assert "INJECTED" not in result.stdout or "hello; echo INJECTED" in result.stdout


class TestToolRegistry:
    def test_registry_register_and_get(self):
        from argus_lite.core.tool_runner import BaseToolRunner, ToolRegistry

        registry = ToolRegistry()
        runner = BaseToolRunner(name="echo", path="/usr/bin/echo")
        registry.register(runner)
        assert registry.get("echo") is runner

    def test_registry_get_missing(self):
        from argus_lite.core.tool_runner import ToolRegistry

        registry = ToolRegistry()
        assert registry.get("nonexistent") is None

    def test_registry_check_all(self):
        from argus_lite.core.tool_runner import BaseToolRunner, ToolRegistry

        registry = ToolRegistry()
        registry.register(BaseToolRunner(name="echo", path="/usr/bin/echo"))
        registry.register(
            BaseToolRunner(name="fake", path="/usr/bin/nonexistent_xyz")
        )
        status = registry.check_all()
        assert status["echo"] is True
        assert status["fake"] is False
