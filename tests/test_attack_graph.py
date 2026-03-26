"""TDD: Tests for Attack Graph — exploit chaining."""

from __future__ import annotations

import pytest

from argus_lite.models.finding import Finding


def _f(title: str, sev: str = "LOW", source: str = "nuclei") -> Finding:
    return Finding(id=f"f-{title}", type="test", severity=sev,
                   title=title, description="", asset="example.com",
                   evidence="", source=source, remediation="fix")


class TestAttackGraph:
    def test_empty_graph(self):
        from argus_lite.core.attack_graph import AttackGraph
        g = AttackGraph()
        assert len(g.nodes) == 0
        assert len(g.edges) == 0

    def test_add_finding_creates_node(self):
        from argus_lite.core.attack_graph import AttackGraph
        g = AttackGraph()
        g.add_finding(_f("SQL Injection in /api/user", source="sqlmap"))
        assert len(g.nodes) >= 1
        assert any("SQL Injection" in n.label for n in g.nodes)

    def test_add_multiple_findings_creates_edges(self):
        from argus_lite.core.attack_graph import AttackGraph
        g = AttackGraph()
        g.add_finding(_f("XSS in search", source="dalfox"))
        g.add_finding(_f("Missing CSRF protection", source="nuclei"))
        # XSS + no CSRF = potential session hijack chain
        assert len(g.nodes) >= 2

    def test_find_paths_to_access(self):
        from argus_lite.core.attack_graph import AttackGraph, AttackEdge, AttackNode
        g = AttackGraph()
        g.nodes = [
            AttackNode(id="n1", type="vulnerability", label="SQLi"),
            AttackNode(id="n2", type="access", label="Database Access"),
        ]
        g.edges = [
            AttackEdge(source_id="n1", target_id="n2",
                       exploit="SQL injection → data exfiltration", probability=0.7),
        ]
        paths = g.find_paths_to("access")
        assert len(paths) >= 1

    def test_highest_impact_path(self):
        from argus_lite.core.attack_graph import AttackGraph, AttackEdge, AttackNode
        g = AttackGraph()
        g.nodes = [
            AttackNode(id="n1", type="vulnerability", label="XSS"),
            AttackNode(id="n2", type="vulnerability", label="SQLi"),
            AttackNode(id="n3", type="access", label="Admin Access"),
        ]
        g.edges = [
            AttackEdge(source_id="n1", target_id="n3", exploit="XSS→session", probability=0.3),
            AttackEdge(source_id="n2", target_id="n3", exploit="SQLi→auth bypass", probability=0.8),
        ]
        best = g.highest_impact_path()
        assert best is not None
        assert best.probability == 0.8

    def test_to_llm_context(self):
        from argus_lite.core.attack_graph import AttackGraph, AttackNode
        g = AttackGraph()
        g.nodes = [AttackNode(id="n1", type="vulnerability", label="XSS in /search")]
        ctx = g.to_llm_context()
        assert "XSS" in ctx

    def test_no_paths_returns_empty(self):
        from argus_lite.core.attack_graph import AttackGraph
        g = AttackGraph()
        assert g.find_paths_to("access") == []

    def test_graph_with_chain(self):
        from argus_lite.core.attack_graph import AttackGraph, AttackEdge, AttackNode
        g = AttackGraph()
        g.nodes = [
            AttackNode(id="xss", type="vulnerability", label="Reflected XSS"),
            AttackNode(id="csrf", type="vulnerability", label="No CSRF protection"),
            AttackNode(id="hijack", type="access", label="Session Hijack"),
        ]
        g.edges = [
            AttackEdge(source_id="xss", target_id="hijack", exploit="XSS→steal cookie", probability=0.6),
            AttackEdge(source_id="csrf", target_id="hijack", exploit="CSRF→action", probability=0.4,
                       requires=["xss"]),
        ]
        paths = g.find_paths_to("access")
        assert len(paths) >= 1
