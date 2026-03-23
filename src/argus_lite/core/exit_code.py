"""Risk level to CLI exit code mapping for CI/CD integration."""

from __future__ import annotations

_LEVELS: dict[str, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def risk_to_exit_code(risk_level: str, fail_on: str) -> int:
    """Return 1 if risk_level >= fail_on threshold (and fail_on is not NONE), else 0.

    Unknown level names default to 0 (NONE).

    Examples:
        risk_to_exit_code("HIGH", "MEDIUM") -> 1  (HIGH >= MEDIUM)
        risk_to_exit_code("LOW", "HIGH")    -> 0  (LOW < HIGH)
        risk_to_exit_code("HIGH", "NONE")   -> 0  (fail_on=NONE never fails)
    """
    rl = _LEVELS.get(risk_level.upper(), 0)
    fo = _LEVELS.get(fail_on.upper(), 0)
    return 1 if fo > 0 and rl >= fo else 0
