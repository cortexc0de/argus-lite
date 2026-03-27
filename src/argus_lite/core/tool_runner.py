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
        self._resolved_path: str | None = None

    def check_available(self) -> bool:
        """Check if tool binary exists and is executable.

        Tries configured path first, then falls back to shutil.which()
        to find the tool anywhere in PATH.
        """
        import shutil

        p = Path(self.path)
        if p.exists() and p.is_file() and _is_executable(p):
            self._resolved_path = self.path
            return True

        # Fallback: search PATH
        found = shutil.which(self.name)
        if found:
            self._resolved_path = found
            return True

        return False

    def _get_executable(self) -> str:
        """Get resolved executable path."""
        return self._resolved_path or self.path

    async def run(self, args: list[str], timeout: int = 300, stdin_data: str | None = None) -> ToolOutput:
        """Run the tool with given arguments. Never uses shell=True."""
        if not self.check_available():
            raise ToolNotFoundError(
                f"Tool '{self.name}' not found at {self.path} or in PATH"
            )

        command = [self._get_executable(), *args]
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin_bytes = stdin_data.encode("utf-8") if stdin_data else None
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout
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
