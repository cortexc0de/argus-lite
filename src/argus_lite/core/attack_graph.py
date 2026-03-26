"""Attack Graph — model exploit chains and lateral movement paths."""

from __future__ import annotations

from pydantic import BaseModel

from argus_lite.models.finding import Finding

# Mapping finding types/sources to potential next-step access levels
_CHAIN_RULES: dict[str, list[tuple[str, str, float]]] = {
    # source → (target_type, exploit_description, probability)
    "xss": [("session_hijack", "XSS → steal session cookie", 0.6)],
    "sqli": [("database_access", "SQLi → exfiltrate data", 0.8),
             ("auth_bypass", "SQLi → bypass authentication", 0.5)],
    "missing_header": [("clickjacking", "Missing X-Frame-Options → clickjack", 0.3)],
    "exposed_service": [("unauthorized_access", "Exposed service → direct access", 0.7)],
    "sensitive_path": [("info_disclosure", "Sensitive path → config/secrets leak", 0.5)],
    "nuclei": [("known_vuln", "Known vulnerability matched by template", 0.4)],
}


class AttackNode(BaseModel):
    """Node in the attack graph: an asset, vulnerability, or access level."""

    id: str
    type: str           # vulnerability, asset, access
    label: str
    data: dict = {}


class AttackEdge(BaseModel):
    """Edge: an exploit path from one node to another."""

    source_id: str
    target_id: str
    exploit: str
    probability: float = 0.5
    requires: list[str] = []


class AttackPath(BaseModel):
    """A multi-hop exploit chain through the attack graph."""

    edges: list[AttackEdge]
    cumulative_probability: float = 0.0
    impact: str = ""
    cost: int = 0       # number of skills/steps needed


class AttackGraph(BaseModel):
    """Incrementally-built graph of exploit chains with search capabilities."""

    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []

    # ── Graph Search (v5) ──

    def search_paths(
        self,
        start_type: str = "vulnerability",
        goal_type: str = "access",
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """BFS pathfinding: find all multi-hop chains from start_type to goal_type.

        Returns paths ranked by cumulative probability (highest first).
        """
        start_ids = {n.id for n in self.nodes if n.type == start_type}
        goal_ids = {n.id for n in self.nodes if n.type == goal_type}

        if not start_ids or not goal_ids:
            return []

        # Build adjacency: source_id → list[edge]
        adj: dict[str, list[AttackEdge]] = {}
        for e in self.edges:
            adj.setdefault(e.source_id, []).append(e)

        # BFS from each start node
        all_paths: list[AttackPath] = []

        for start_id in start_ids:
            # Queue: (current_node_id, path_edges_so_far)
            queue: list[tuple[str, list[AttackEdge]]] = [(start_id, [])]
            visited_in_path: set[str] = set()

            while queue:
                current, path = queue.pop(0)

                if len(path) >= max_depth:
                    continue

                for edge in adj.get(current, []):
                    if edge.target_id in visited_in_path:
                        continue  # avoid cycles

                    new_path = path + [edge]

                    if edge.target_id in goal_ids:
                        # Found a path to goal
                        prob = 1.0
                        for e in new_path:
                            prob *= e.probability
                        goal_node = next((n for n in self.nodes if n.id == edge.target_id), None)
                        all_paths.append(AttackPath(
                            edges=new_path,
                            cumulative_probability=round(prob, 4),
                            impact=goal_node.label if goal_node else edge.target_id,
                            cost=len(new_path),
                        ))
                    else:
                        # Continue searching
                        queue.append((edge.target_id, new_path))

        # Sort by cumulative probability (highest first)
        all_paths.sort(key=lambda p: p.cumulative_probability, reverse=True)
        return all_paths

    def update_probability(self, source_id: str, target_id: str, success: bool) -> None:
        """Bayesian update: adjust edge probability based on exploit outcome."""
        for edge in self.edges:
            if edge.source_id == source_id and edge.target_id == target_id:
                if success:
                    edge.probability = min(1.0, edge.probability * 1.3)
                else:
                    edge.probability = max(0.01, edge.probability * 0.6)
                break

    def get_exploitable_chains(self, threshold: float = 0.3) -> list[AttackPath]:
        """Find chains where cumulative probability exceeds threshold."""
        paths = self.search_paths()
        return [p for p in paths if p.cumulative_probability >= threshold]

    # ── Original methods ──

    def add_finding(self, finding: Finding) -> None:
        """Add a finding as a vulnerability node + chain edges."""
        node_id = f"vuln-{finding.id}"

        # Skip if already added
        if any(n.id == node_id for n in self.nodes):
            return

        self.nodes.append(AttackNode(
            id=node_id,
            type="vulnerability",
            label=finding.title,
            data={"severity": finding.severity, "source": finding.source, "asset": finding.asset},
        ))

        # Auto-create chain edges based on finding type
        chains = _CHAIN_RULES.get(finding.type, _CHAIN_RULES.get(finding.source, []))
        for target_type, exploit_desc, prob in chains:
            target_id = f"access-{target_type}"
            # Ensure target node exists
            if not any(n.id == target_id for n in self.nodes):
                self.nodes.append(AttackNode(id=target_id, type="access", label=target_type))
            self.edges.append(AttackEdge(
                source_id=node_id, target_id=target_id,
                exploit=exploit_desc, probability=prob,
            ))

    def find_paths_to(self, target_type: str) -> list[AttackEdge]:
        """Find all edges leading to nodes of the given type."""
        target_ids = {n.id for n in self.nodes if n.type == target_type}
        return [e for e in self.edges if e.target_id in target_ids]

    def highest_impact_path(self) -> AttackEdge | None:
        """Return the single edge with highest probability to an access node."""
        access_edges = self.find_paths_to("access")
        if not access_edges:
            return None
        return max(access_edges, key=lambda e: e.probability)

    def to_llm_context(self) -> str:
        """Render graph as text for LLM prompt."""
        if not self.nodes:
            return "Attack graph: empty (no findings yet)"

        lines = [f"Attack graph: {len(self.nodes)} nodes, {len(self.edges)} edges"]
        vuln_nodes = [n for n in self.nodes if n.type == "vulnerability"]
        access_nodes = [n for n in self.nodes if n.type == "access"]

        if vuln_nodes:
            lines.append("Vulnerabilities:")
            for n in vuln_nodes[:10]:
                lines.append(f"  - {n.label}")

        if self.edges:
            lines.append("Exploit chains:")
            for e in self.edges[:10]:
                src = next((n.label for n in self.nodes if n.id == e.source_id), e.source_id)
                tgt = next((n.label for n in self.nodes if n.id == e.target_id), e.target_id)
                lines.append(f"  {src} → {tgt} (p={e.probability:.1f}): {e.exploit}")

        if access_nodes:
            lines.append(f"Potential access: {', '.join(n.label for n in access_nodes)}")

        return "\n".join(lines)
