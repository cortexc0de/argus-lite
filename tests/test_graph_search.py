"""TDD: Tests for Attack Graph Search — multi-hop exploit chain pathfinding."""

from __future__ import annotations

import pytest

from argus_lite.core.attack_graph import AttackEdge, AttackGraph, AttackNode, AttackPath
from argus_lite.models.finding import Finding


def _graph_with_chain() -> AttackGraph:
    """Build a graph: XSS → SessionHijack (pivot) → AdminAccess."""
    g = AttackGraph()
    g.nodes = [
        AttackNode(id="xss", type="vulnerability", label="Reflected XSS"),
        AttackNode(id="hijack", type="pivot", label="Session Hijack"),
        AttackNode(id="admin", type="access", label="Admin Access"),
    ]
    g.edges = [
        AttackEdge(source_id="xss", target_id="hijack", exploit="XSS steals cookie", probability=0.6),
        AttackEdge(source_id="hijack", target_id="admin", exploit="Hijacked session → admin", probability=0.7),
    ]
    return g


class TestGraphSearch:
    def test_finds_two_hop_chain(self):
        g = _graph_with_chain()
        paths = g.search_paths(start_type="vulnerability", goal_type="access")
        assert len(paths) >= 1
        two_hop = [p for p in paths if len(p.edges) == 2]
        assert len(two_hop) >= 1
        assert two_hop[0].impact == "Admin Access"

    def test_cumulative_probability(self):
        g = _graph_with_chain()
        paths = g.search_paths()
        two_hop = [p for p in paths if len(p.edges) == 2]
        assert len(two_hop) >= 1
        assert abs(two_hop[0].cumulative_probability - 0.42) < 0.01  # 0.6 * 0.7

    def test_direct_path(self):
        g = AttackGraph()
        g.nodes = [
            AttackNode(id="sqli", type="vulnerability", label="SQLi"),
            AttackNode(id="db", type="access", label="DB Access"),
        ]
        g.edges = [AttackEdge(source_id="sqli", target_id="db", exploit="SQLi→DB", probability=0.8)]
        paths = g.search_paths()
        assert len(paths) == 1
        assert paths[0].cost == 1

    def test_no_path_returns_empty(self):
        g = AttackGraph()
        g.nodes = [AttackNode(id="a", type="vulnerability", label="X")]
        assert g.search_paths() == []

    def test_max_depth_respected(self):
        g = _graph_with_chain()
        paths = g.search_paths(max_depth=1)
        # Should NOT find the 2-hop chain
        two_hop = [p for p in paths if len(p.edges) == 2]
        assert len(two_hop) == 0

    def test_ranked_by_probability(self):
        g = AttackGraph()
        g.nodes = [
            AttackNode(id="v1", type="vulnerability", label="XSS"),
            AttackNode(id="v2", type="vulnerability", label="SQLi"),
            AttackNode(id="acc", type="access", label="Access"),
        ]
        g.edges = [
            AttackEdge(source_id="v1", target_id="acc", exploit="XSS→access", probability=0.3),
            AttackEdge(source_id="v2", target_id="acc", exploit="SQLi→access", probability=0.9),
        ]
        paths = g.search_paths()
        assert paths[0].cumulative_probability > paths[1].cumulative_probability


class TestBayesianUpdate:
    def test_success_increases_probability(self):
        g = _graph_with_chain()
        old_prob = g.edges[0].probability
        g.update_probability("xss", "hijack", success=True)
        assert g.edges[0].probability > old_prob

    def test_failure_decreases_probability(self):
        g = _graph_with_chain()
        old_prob = g.edges[0].probability
        g.update_probability("xss", "hijack", success=False)
        assert g.edges[0].probability < old_prob

    def test_probability_capped_at_one(self):
        g = AttackGraph()
        g.edges = [AttackEdge(source_id="a", target_id="b", exploit="test", probability=0.95)]
        g.update_probability("a", "b", success=True)
        g.update_probability("a", "b", success=True)
        g.update_probability("a", "b", success=True)
        assert g.edges[0].probability <= 1.0

    def test_probability_floor_at_zero(self):
        g = AttackGraph()
        g.edges = [AttackEdge(source_id="a", target_id="b", exploit="test", probability=0.1)]
        for _ in range(20):
            g.update_probability("a", "b", success=False)
        assert g.edges[0].probability >= 0.0
