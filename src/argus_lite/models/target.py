"""Target validation models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class Target(BaseModel):
    """Validated scan target."""

    raw: str  # Original user input
    value: str  # Sanitized value
    type: Literal["domain", "ip"]
