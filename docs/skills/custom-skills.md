# Custom Skills

Create your own skills as markdown files that Argus auto-loads and makes available to the AI agent.

## Quick Start

1. Create a `.md` file in `~/.argus-lite/skills/`:

```markdown
---
name: check_wordpress
description: WordPress-specific security checks
tools: [nuclei, httpx]
---

1. Probe /wp-admin and /wp-login.php for accessibility
2. Run nuclei with wordpress tags
3. Check xmlrpc.php exposure
4. Test for user enumeration via ?author=1
```

2. Run the agent — your skill is automatically available:

```bash
argus agent example.com
```

The agent sees your skill in its available skills list and can choose to use it.

## File Format

### Frontmatter (required)

YAML between `---` delimiters:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Unique skill identifier (snake_case) |
| `description` | Yes | string | One-line description shown to the agent |
| `tools` | No | list[str] | External tools this skill uses (informational) |

### Body (steps)

Numbered steps (`1. ...`, `2. ...`) that describe what the skill does. These are passed to the agent as structured data.

## Examples

### API Security Check

```markdown
---
name: api_security_audit
description: Comprehensive API endpoint security testing
tools: [nuclei, httpx]
---

1. Discover API endpoints from crawled URLs
2. Test for IDOR by manipulating ID parameters
3. Check for missing authentication on admin endpoints
4. Test rate limiting by sending rapid requests
5. Verify CORS configuration
```

### Cloud Misconfiguration

```markdown
---
name: check_cloud_misconfig
description: Detect common cloud service misconfigurations
tools: [nuclei, httpx]
---

1. Check for exposed .env files and configuration endpoints
2. Test S3 bucket permissions if AWS detected
3. Check for exposed debug endpoints (Laravel Telescope, Django Debug)
4. Verify that error pages don't leak stack traces
```

### GraphQL Enumeration

```markdown
---
name: graphql_enum
description: GraphQL introspection and vulnerability testing
tools: [httpx]
---

1. Send introspection query to /graphql endpoint
2. Map all types, queries, and mutations
3. Identify ID-based fields for IDOR testing
4. Check for disabled introspection on production
```

## Custom Skills Directory

Default: `~/.argus-lite/skills/`

Override via CLI:
```bash
argus agent example.com --skills-dir /path/to/my/skills
```

Or in config (`~/.argus-lite/config.yaml`):
```yaml
skills:
  dirs:
    - ~/.argus-lite/skills
    - /shared/team-skills
```

## How Custom Skills Work

1. On startup, `build_skill_registry()` scans configured directories for `.md` files
2. Each valid file is parsed into a `SkillDefinition` (name, description, tools, steps)
3. A `MarkdownSkill` wrapper is created and registered in the `SkillRegistry`
4. The agent sees the skill in its available skills list
5. When the agent chooses the skill, it receives the structured steps as data

Custom skills **do not override** built-in skills with the same name. If a name conflict exists, the custom skill is skipped.
