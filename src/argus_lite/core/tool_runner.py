"""ToolRunner abstraction for safe subprocess execution."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path


class ToolNotFoundError(Exception):
    """Raised when tool binary is not found."""


class ToolTimeoutError(Exception):
    """Raised when tool execution exceeds timeout."""


@dataclass
class ToolOutput:
    """Result of a tool execution."""

    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: list[str]

    @property
    def success(self) -> bool:
        return self.returncode == 0


class BaseToolRunner:
    """Base implementation for running external tools safely.

    Rules:
    - NEVER uses shell=True
    - Arguments are ALWAYS passed as a list
    - Timeouts enforced via asyncio.wait_for
    """

    def __init__(self, name: str, path: str) -> None:
        self.name = name
        self.path = path

    def check_available(self) -> bool:
        """Check if tool binary exists and is executable."""
        p = Path(self.path)
        return p.exists() and p.is_file() and _is_executable(p)

    async def run(self, args: list[str], timeout: int = 300) -> ToolOutput:
        """Run the tool with given arguments. Never uses shell=True."""
        if not self.check_available():
            raise ToolNotFoundError(
                f"Tool '{self.name}' not found at {self.path}"
            )

        command = [self.path, *args]
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            # Kill the process on timeout
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.returncode is None:
                    proc.kill()
            except ProcessLookupError:
                pass
            raise ToolTimeoutError(
                f"Tool '{self.name}' timed out after {timeout}s"
            )
        except FileNotFoundError:
            raise ToolNotFoundError(
                f"Tool '{self.name}' not found at {self.path}"
            )

        elapsed = time.monotonic() - start

        return ToolOutput(
            returncode=proc.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_seconds=round(elapsed, 3),
            command=command,
        )

    def parse(self, raw_output: str) -> dict:
        """Parse raw output. Override in subclasses."""
        return {"raw": raw_output}


class ToolRegistry:
    """Registry of available tool runners."""

    def __init__(self) -> None:
        self._runners: dict[str, BaseToolRunner] = {}

    def register(self, runner: BaseToolRunner) -> None:
        self._runners[runner.name] = runner

    def get(self, name: str) -> BaseToolRunner | None:
        return self._runners.get(name)

    def check_all(self) -> dict[str, bool]:
        """Check availability of all registered tools."""
        return {name: runner.check_available() for name, runner in self._runners.items()}

    def list_tools(self) -> list[str]:
        return list(self._runners.keys())


def _is_executable(path: Path) -> bool:
    """Check if file has execute permission."""
    import os
    return os.access(path, os.X_OK)
