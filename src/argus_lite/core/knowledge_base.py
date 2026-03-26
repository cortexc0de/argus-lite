"""Knowledge Base — structured exploit knowledge, not just patterns.

Stores conditional knowledge:
  "WordPress AJAX + no nonce validation → CSRF + XSS chain"
  "GraphQL introspection enabled → query all types → find IDOR"
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path.home() / ".argus-lite" / "agent" / "knowledge.json"


class ExploitKnowledge(BaseModel):
    """A structured piece of exploit knowledge."""

    id: str
    tech: str                      # WordPress, Laravel, GraphQL, etc.
    conditions: list[str]          # what must be true for this to apply
    exploit_type: str              # XSS, SQLi, CSRF, IDOR, etc.
    exploit_chain: list[str]       # step-by-step exploit
    payloads: list[str] = []       # proven payloads
    success_count: int = 0
    fail_count: int = 0
    confidence: float = 0.5

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return self.success_count / total if total > 0 else 0.5


# Built-in exploit knowledge (research-grade)
_BUILTIN_KNOWLEDGE: list[dict] = [
    {
        "id": "wp-ajax-csrf",
        "tech": "wordpress",
        "conditions": ["ajax endpoint detected", "no nonce validation"],
        "exploit_type": "csrf",
        "exploit_chain": ["Find admin-ajax.php", "Identify action without nonce", "Craft CSRF payload", "Chain with stored XSS if forms present"],
        "payloads": [],
        "confidence": 0.7,
    },
    {
        "id": "graphql-introspection",
        "tech": "graphql",
        "conditions": ["graphql endpoint found", "introspection enabled"],
        "exploit_type": "idor",
        "exploit_chain": ["Send introspection query", "Map all types and fields", "Find queries with ID params", "Test IDOR on user/order/payment queries"],
        "payloads": ['{"query":"{__schema{types{name,fields{name}}}}"}'],
        "confidence": 0.8,
    },
    {
        "id": "laravel-debug",
        "tech": "laravel",
        "conditions": ["debug mode enabled", "stack trace in response"],
        "exploit_type": "info_disclosure",
        "exploit_chain": ["Trigger error to get stack trace", "Extract .env path", "Try /.env endpoint", "Read database credentials"],
        "payloads": ["/%00", "/nonexistent-route-to-trigger-error"],
        "confidence": 0.6,
    },
    {
        "id": "jwt-none-alg",
        "tech": "jwt",
        "conditions": ["JWT in cookies or headers", "auth endpoint detected"],
        "exploit_type": "auth_bypass",
        "exploit_chain": ["Decode JWT", "Set alg to none", "Remove signature", "Send modified token"],
        "confidence": 0.4,
    },
    {
        "id": "ssrf-redirect",
        "tech": "any",
        "conditions": ["redirect parameter found", "URL parameter in query"],
        "exploit_type": "ssrf",
        "exploit_chain": ["Test with external URL", "Test with internal IP (127.0.0.1)", "Test with cloud metadata (169.254.169.254)", "Check response for internal data"],
        "payloads": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
        "confidence": 0.5,
    },
    {
        "id": "file-upload-rce",
        "tech": "any",
        "conditions": ["file upload endpoint found"],
        "exploit_type": "rce",
        "exploit_chain": ["Upload PHP/JSP webshell with double extension", "Bypass content-type check", "Find uploaded file path", "Execute commands"],
        "payloads": ["shell.php.jpg", "shell.phtml"],
        "confidence": 0.3,
    },
]


class KnowledgeBase:
    """Structured exploit knowledge — conditions + chains + payloads."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_PATH
        self._knowledge: list[ExploitKnowledge] = []
        self._load_builtin()

    def _load_builtin(self) -> None:
        for entry in _BUILTIN_KNOWLEDGE:
            self._knowledge.append(ExploitKnowledge(**entry))

    def load(self) -> None:
        """Load user-discovered knowledge from disk."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for entry in data.get("knowledge", []):
                self._knowledge.append(ExploitKnowledge(**entry))
        except Exception as exc:
            logger.debug("Failed to load knowledge base: %s", exc)

    def save(self) -> None:
        """Save knowledge to disk (only user-discovered, not builtin)."""
        user_knowledge = [k for k in self._knowledge if k.id not in
                          {bk["id"] for bk in _BUILTIN_KNOWLEDGE}]
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {"knowledge": [k.model_dump() for k in user_knowledge]}
            self._path.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            logger.debug("Failed to save knowledge base: %s", exc)

    def query(self, tech: str = "", conditions: list[str] | None = None) -> list[ExploitKnowledge]:
        """Find applicable knowledge for given tech and conditions."""
        results = []
        tech_lower = tech.lower()
        cond_lower = {c.lower() for c in (conditions or [])}

        for k in self._knowledge:
            # Match tech
            if k.tech != "any" and tech_lower and k.tech.lower() not in tech_lower:
                continue
            # Match conditions (any overlap)
            k_conds = {c.lower() for c in k.conditions}
            if cond_lower and not (k_conds & cond_lower):
                if k.tech != "any":
                    continue
            results.append(k)

        # Sort by confidence × success_rate
        results.sort(key=lambda k: k.confidence * k.success_rate, reverse=True)
        return results

    def add_knowledge(self, knowledge: ExploitKnowledge) -> None:
        """Add new exploit knowledge (learned from successful attacks)."""
        self._knowledge.append(knowledge)

    def record_outcome(self, knowledge_id: str, success: bool) -> None:
        """Update success/fail counts for a piece of knowledge."""
        for k in self._knowledge:
            if k.id == knowledge_id:
                if success:
                    k.success_count += 1
                    k.confidence = min(1.0, k.confidence * 1.1)
                else:
                    k.fail_count += 1
                    k.confidence = max(0.1, k.confidence * 0.9)
                break

    def to_llm_context(self, tech_stack: list[str]) -> str:
        """Generate context for LLM from applicable knowledge."""
        relevant = []
        for tech in tech_stack:
            relevant.extend(self.query(tech=tech))

        if not relevant:
            return ""

        # Deduplicate
        seen: set[str] = set()
        unique = []
        for k in relevant:
            if k.id not in seen:
                seen.add(k.id)
                unique.append(k)

        lines = ["Known exploit patterns:"]
        for k in unique[:8]:
            lines.append(f"  [{k.exploit_type}] {k.tech}: {' → '.join(k.exploit_chain[:3])} (conf={k.confidence:.1f})")
            if k.payloads:
                lines.append(f"    Payloads: {k.payloads[0][:60]}")

        return "\n".join(lines)
