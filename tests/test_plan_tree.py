"""TDD: Tests for Plan Tree — branching attack strategies."""

from __future__ import annotations

import pytest


class TestPlanNode:
    def test_create_node(self):
        from argus_lite.core.agent_context import PlanNode
        node = PlanNode(id="n1", action="scan_nuclei", description="Run nuclei")
        assert node.status == "pending"
        assert node.confidence == 0.5

    def test_node_with_children(self):
        from argus_lite.core.agent_context import PlanNode
        child1 = PlanNode(id="c1", action="scan_xss", confidence=0.8)
        child2 = PlanNode(id="c2", action="scan_sqli", confidence=0.6)
        root = PlanNode(id="root", action="branch", children=[child1, child2])
        assert len(root.children) == 2


class TestPlanTree:
    def test_get_next_node_returns_highest_confidence(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", status="completed", children=[
            PlanNode(id="a", action="scan_xss", confidence=0.9),
            PlanNode(id="b", action="scan_sqli", confidence=0.3),
        ])
        tree = PlanTree(goal="Test vulns", root=root)
        nxt = tree.get_next_node()
        assert nxt is not None
        assert nxt.id == "a"  # highest confidence pending

    def test_get_next_node_skips_completed(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", status="completed", children=[
            PlanNode(id="a", action="scan_xss", confidence=0.9, status="completed"),
            PlanNode(id="b", action="scan_sqli", confidence=0.3),
        ])
        tree = PlanTree(goal="Test", root=root)
        nxt = tree.get_next_node()
        assert nxt.id == "b"

    def test_get_next_node_none_when_all_done(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="done", status="completed")
        tree = PlanTree(goal="Done", root=root)
        assert tree.get_next_node() is None

    def test_mark_completed(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", children=[
            PlanNode(id="a", action="scan_xss"),
        ])
        tree = PlanTree(goal="Test", root=root)
        tree.mark_completed("a", "Found 2 XSS")
        assert root.children[0].status == "completed"
        assert root.children[0].result_summary == "Found 2 XSS"

    def test_mark_failed(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", children=[
            PlanNode(id="a", action="scan_sqli"),
        ])
        tree = PlanTree(goal="Test", root=root)
        tree.mark_failed("a", "Tool not found")
        assert root.children[0].status == "failed"

    def test_add_branch(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", children=[
            PlanNode(id="a", action="scan_nuclei"),
        ])
        tree = PlanTree(goal="Test", root=root)
        new_node = PlanNode(id="b", action="scan_xss", confidence=0.8)
        tree.add_branch("root", new_node)
        assert len(root.children) == 2

    def test_deep_tree_traversal(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", status="completed", children=[
            PlanNode(id="a", action="branch", status="completed", children=[
                PlanNode(id="a1", action="scan_xss", confidence=0.7, status="completed"),
                PlanNode(id="a2", action="test_payload", confidence=0.9),
            ]),
            PlanNode(id="b", action="scan_sqli", confidence=0.5),
        ])
        tree = PlanTree(goal="Deep", root=root)
        nxt = tree.get_next_node()
        assert nxt.id == "a2"  # deepest pending with highest confidence

    def test_to_llm_context(self):
        from argus_lite.core.agent_context import PlanNode, PlanTree
        root = PlanNode(id="root", action="branch", children=[
            PlanNode(id="a", action="scan_xss", status="completed", result_summary="found 1"),
            PlanNode(id="b", action="scan_sqli", status="pending"),
        ])
        tree = PlanTree(goal="Test APIs", root=root)
        ctx = tree.to_llm_context()
        assert "Test APIs" in ctx
        assert "scan_xss" in ctx
        assert "✓" in ctx  # completed icon
