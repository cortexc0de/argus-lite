"""Audit logging with JSON entries and secret masking."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

# Patterns that indicate sensitive data in keys
_SENSITIVE_KEY_PATTERNS = re.compile(
    r"(key|secret|token|password|api_key|credential)", re.IGNORECASE
)


class AuditLogger:
    """Append-only JSON audit logger with secret masking."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        # Ensure parent directory exists
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, **kwargs: str) -> None:
        """Log an audit entry as a single JSON line."""
        entry = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "action": action,
        }
        for key, value in kwargs.items():
            entry[key] = self._mask_if_sensitive(key, value)

        with self._log_path.open("a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    @staticmethod
    def _mask_if_sensitive(key: str, value: str) -> str:
        """Mask values that look like secrets."""
        if _SENSITIVE_KEY_PATTERNS.search(key) and value:
            return "***"
        return value
