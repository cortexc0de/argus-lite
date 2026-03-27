# Skill System Overview

Skills are the interface between the AI agent and external security tools. Each skill wraps a tool with a uniform `execute(params, context) → SkillResult` interface.

## Architecture

```
LLM Agent
    │
    ▼
SkillRegistry (manages all skills)
    │
    ├── Built-in Skills (11)  ← Python classes in skills.py
    └── Custom Skills (N)     ← Markdown files in ~/.argus-lite/skills/
         │
         ▼
    SkillResult { success, data, findings, summary }
```

## How Skills Work

1. The LLM agent decides which skill to run based on current context
2. The agent sends JSON: `{"action": "scan_nuclei", "input": {"target": "example.com"}}`
3. `SkillRegistry.execute()` finds the skill and calls `skill.execute(params, context)`
4. The skill runs the underlying tool and returns structured results
5. Results feed back into the agent's context for the next decision

## Skill Interface

Every skill implements:

```python
class Skill(ABC):
    @property
    def name(self) -> str: ...       # e.g., "scan_nuclei"

    @property
    def description(self) -> str: ... # e.g., "Scan for known vulnerabilities"

    async def execute(self, params: dict, context: AgentContext) -> SkillResult: ...

    def is_available(self) -> bool: ... # True if underlying tool exists
```

## Two Types of Skills

### Built-in Skills
Python classes in `src/argus_lite/core/skills.py`. Each wraps a specific tool binary. See [Built-in Skills](built-in-skills.md).

### Custom Markdown Skills
User-defined `.md` files with YAML frontmatter. Loaded from `~/.argus-lite/skills/` or `--skills-dir`. See [Custom Skills](custom-skills.md).
