# Changelog

All notable changes to Argus are documented here.

## [6.0.0] - 2025-05-15

### Added
- **Goal Hierarchy** — mission-driven planning (`--mission data_exfiltration|admin_access|rce`)
- **Knowledge Base** — 6 built-in exploit patterns (WordPress CSRF, GraphQL IDOR, Laravel debug, JWT bypass, SSRF redirect, file upload)
- **Meta-Learning** — skill effectiveness tracking per technology, auto-adjusts strategy
- **Markdown Skill System** — define custom skills as `.md` files in `~/.argus-lite/skills/`
- `--skills-dir` CLI option for agent command

### Fixed
- Finding severity enum: expanded from `INFO|LOW` to `INFO|LOW|MEDIUM|HIGH|CRITICAL`
- Nuclei severity mapping: was inverting HIGH to LOW
- DNSX targets were computed but never passed to the tool
- ScanNucleiSkill and FuzzPathsSkill now return Finding objects
- XSS findings severity: LOW → MEDIUM; SQLi: LOW → HIGH
- All `except Exception` blocks now log diagnostics
- Extracted shared constants: `VALID_SEVERITIES`, `SENSITIVE_PATHS`, `nuclei_finding_to_finding()`

## [5.0.0] - 2025-04-20

### Added
- **Graph Search** — BFS multi-hop exploit chain pathfinding with Bayesian probability updates
- **Environment Detection** — WAF/CDN fingerprinting (Cloudflare, ModSecurity, Imperva, Akamai, Sucuri, AWS WAF, F5)
- **Pattern Learning** — generalizes from past experience (tech → vuln type → confidence)
- **Stealth Mode** — `--stealth` flag for slow probing, header randomization, WAF evasion

## [4.0.0] - 2025-03-25

### Added
- **Plan Trees** — branching attack strategies with confidence scoring (DFS next-node selection)
- **Attack Graphs** — findings connect into exploit chains with probability edges
- **Adaptive Payload Engine** — iterative refinement: try → analyze → refine → retry
- **Target Scoring** — endpoints scored CRITICAL/HIGH/MEDIUM/LOW/SKIP before execution
- **Multi-Agent Mode** — `--multi-agent` flag: Recon + Vuln Scanner + Exploit agents
- **Smart Memory** — Jaccard similarity, cross-target learning across sessions

## [3.0.0] - 2025-03-10

### Added
- **Closed execution loop** — skills actually execute tools (not just printed)
- `AgentPlanner` — LLM-powered attack planning with adaptive replanning
- `SkillRegistry` — 11 skills with uniform `execute()` interface
- `AgentMemory` — persistent cross-session memory with target patterns

## [2.0.0] - 2025-02-20

### Added
- **Agent mode** — LLM-reactive autonomous pentesting (`argus agent`)
- Elite tools: Dalfox (XSS), SQLMap (SQLi), Interactsh (OOB)
- JWT authentication for dashboard
- Threat intelligence integration

## [1.8.0] - 2025-02-10

### Added
- Web dashboard v2 (Flask + htmx + REST API + Chart.js)
- Scan comparison API (`/api/compare`)

## [1.6.0] - 2025-02-01

### Added
- Continuous monitoring with diff detection and notifications
- Enhanced AI: Russian language support, remediation commands

## [1.5.0] - 2025-01-25

### Added
- Full TUI with 5 tabs (Scan, Settings, Results, OSINT, Monitor)
- Vulnerability discovery engine (Shodan/Censys/ZoomEye/FOFA parallel search)

## [1.3.0] - 2025-01-15

### Added
- Censys, ZoomEye, FOFA, GreyNoise OSINT API integrations
- 7 OSINT APIs total

## [1.2.0] - 2025-01-08

### Added
- Bulk scanner (file, CIDR, ASN input)
- Semaphore-based concurrency control

## [1.1.0] - 2025-01-03

### Added
- CVE correlation via NVD API v2.0
- YAML scan templates
- GitHub Actions integration
- Docker support (multi-platform)

## [1.0.0] - 2024-12-20

### Added
- Initial release: 11 tools, 3 OSINT APIs
- Smart pipeline with parallel execution groups
- Risk scoring and HTML/JSON/Markdown/SARIF reports
