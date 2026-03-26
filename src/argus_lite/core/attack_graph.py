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


class AttackGraph(BaseModel):
    """Incrementally-built graph of exploit chains."""

    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []

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
