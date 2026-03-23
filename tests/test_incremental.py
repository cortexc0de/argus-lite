"""TDD: Tests for incremental scan diff engine."""

import pytest

from argus_lite.models.finding import Finding


def _f(id: str, title: str, sev: str = "INFO") -> Finding:
    return Finding(id=id, type="test", severity=sev, title=title,
                   description="d", asset="a", evidence="e", source="s", remediation="r")


class TestScanDiff:
    def test_new_findings(self):
        from argus_lite.core.incremental import diff_findings

        old = [_f("f1", "A")]
        new = [_f("f1", "A"), _f("f2", "B")]
        result = diff_findings(old, new)
        assert len(result.new) == 1
        assert result.new[0].id == "f2"

    def test_resolved_findings(self):
        from argus_lite.core.incremental import diff_findings

        old = [_f("f1", "A"), _f("f2", "B")]
        new = [_f("f1", "A")]
        result = diff_findings(old, new)
        assert len(result.resolved) == 1
        assert result.resolved[0].id == "f2"

    def test_unchanged_findings(self):
        from argus_lite.core.incremental import diff_findings

        old = [_f("f1", "A")]
        new = [_f("f1", "A")]
        result = diff_findings(old, new)
        assert len(result.unchanged) == 1
        assert result.new == []
        assert result.resolved == []

    def test_all_new(self):
        from argus_lite.core.incremental import diff_findings

        result = diff_findings([], [_f("f1", "A"), _f("f2", "B")])
        assert len(result.new) == 2
        assert result.resolved == []

    def test_all_resolved(self):
        from argus_lite.core.incremental import diff_findings

        result = diff_findings([_f("f1", "A")], [])
        assert len(result.resolved) == 1
        assert result.new == []

    def test_empty_both(self):
        from argus_lite.core.incremental import diff_findings

        result = diff_findings([], [])
        assert result.new == []
        assert result.resolved == []
        assert result.unchanged == []

    def test_diff_summary(self):
        from argus_lite.core.incremental import diff_findings

        old = [_f("f1", "A"), _f("f2", "B")]
        new = [_f("f1", "A"), _f("f3", "C")]
        result = diff_findings(old, new)
        summary = result.summary()
        assert summary["new"] == 1
        assert summary["resolved"] == 1
        assert summary["unchanged"] == 1


class TestNewSubdomains:
    def test_diff_subdomains(self):
        from argus_lite.core.incremental import diff_lists

        old = ["www.example.com", "api.example.com"]
        new = ["www.example.com", "api.example.com", "dev.example.com"]
        added, removed = diff_lists(old, new)
        assert added == ["dev.example.com"]
        assert removed == []

    def test_removed_subdomains(self):
        from argus_lite.core.incremental import diff_lists

        old = ["www.example.com", "old.example.com"]
        new = ["www.example.com"]
        added, removed = diff_lists(old, new)
        assert added == []
        assert removed == ["old.example.com"]
