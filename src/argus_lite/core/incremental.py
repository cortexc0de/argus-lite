"""Incremental scan diff engine — compare old vs new findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from argus_lite.models.finding import Finding


@dataclass
class DiffResult:
    """Result of comparing two sets of findings."""

    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "unchanged": len(self.unchanged),
        }


def diff_findings(
    old: list[Finding], new: list[Finding]
) -> DiffResult:
    """Compare old and new findings by title (case-insensitive).

    Returns:
        DiffResult with new, resolved, and unchanged findings.
    """
    old_by_title = {f.title.lower(): f for f in old}
    new_by_title = {f.title.lower(): f for f in new}

    result = DiffResult()

    for title, finding in new_by_title.items():
        if title in old_by_title:
            result.unchanged.append(finding)
        else:
            result.new.append(finding)

    for title, finding in old_by_title.items():
        if title not in new_by_title:
            result.resolved.append(finding)

    return result


def diff_lists(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    """Diff two lists of strings. Returns (added, removed)."""
    old_set = set(old)
    new_set = set(new)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return added, removed
