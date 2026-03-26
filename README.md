<p align="center">
  <h1 align="center">ARGUS</h1>
  <p align="center">
    <strong>Autonomous AI pentesting framework for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#agent-mode">Agent Mode</a> •
    <a href="#multi-agent">Multi-Agent</a> •
    <a href="#skill-system">Skills</a> •
    <a href="#commands">Commands</a> •
    <a href="#web-dashboard">Dashboard</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-4.0.0-00ff41?style=flat-square" alt="Version">
    <img src="https://img.shields.io/badge/tests-675_passed-brightgreen?style=flat-square" alt="Tests">
    <img src="https://img.shields.io/badge/tools-15-orange?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/skills-11-ff6b6b?style=flat-square" alt="Skills">
    <img src="https://img.shields.io/badge/OSINT_APIs-7-blue?style=flat-square" alt="OSINT">
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  </p>
</p>

---

Argus is an **autonomous AI pentesting agent** — the LLM acts as a thinking attacker: it builds branching attack plans, chains exploits into attack graphs, scores targets by value, refines payloads iteratively, and coordinates specialized sub-agents.

```
LLM = brain (plans, decides, adapts)
Skills = hands (executes real tools)
Memory = experience (learns across sessions)
```

> **Legal:** For authorized security testing only. Always obtain written permission.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           LLM Agent (brain)             │
│                                         │
│  Plan Tree → Target Scoring →          │
│  Skill Execution → Attack Graph →      │
│  Adaptive Payloads → Memory →          │
│  Adapt → Repeat                        │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  Multi-Agent Team (v4)                  │
│                                         │
│  Recon Agent    → subdomains, ports     │
│  Vuln Scanner   → nuclei, headers, ffuf │
│  Exploit Agent  → XSS, SQLi, payloads   │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  Skill System (11 skills)               │
│  enumerate_subdomains  probe_http        │
│  crawl_site   scan_nuclei  fuzz_paths   │
│  scan_xss (Dalfox)  scan_sqli (SQLMap)  │
│  check_headers  detect_tech  scan_ports │
│  test_payload (adaptive HTTP)           │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  15 Tools + 7 OSINT APIs                │
│  subfinder httpx katana nuclei naabu    │
│  ffuf dalfox sqlmap dnsx tlsx gau       │
│  gowitness whatweb interactsh gf        │
│  Shodan Censys ZoomEye FOFA GreyNoise   │
│  VirusTotal SecurityTrails              │
└─────────────────────────────────────────┘
```

---

## Agent Mode

```bash
argus agent example.com               # autonomous single agent
argus agent example.com --multi-agent # specialized 3-agent team
argus agent example.com --max-steps 15
```

### How it works (v4)

**1. Plan Tree** — LLM builds branching attack strategies, not a linear list:
```
Goal: "Find data access vulnerabilities"
├── Branch A: API testing (confidence=0.9)
│   ├── scan_sqli /api/user?id=    [pending]
│   └── test_payload custom bypass [pending]
└── Branch B: Auth bypass (confidence=0.6)
    ├── check_headers              [completed ✓]
    └── scan_nuclei /login         [pending]
```
Agent always picks the highest-confidence pending node next.

**2. Attack Graph** — findings connect into exploit chains:
```
XSS in /search ──────────────────→ Session Hijack (p=0.6)
SQLi in /api/user?id ──────────── → Database Access (p=0.8)
SQLi in /api/user?id ──────────── → Auth Bypass (p=0.5)
Missing CSRF protection ──────────→ Clickjacking (p=0.3)
```
LLM sees the graph and prioritizes high-probability chains.

**3. Target Scoring** — endpoints scored before execution:
```
CRITICAL  /admin              → auth_bypass, IDOR
HIGH      /api/user?id=123    → IDOR, SQLi
HIGH      /redirect?url=      → SSRF, open_redirect
HIGH      /graphql             → introspection, IDOR
MEDIUM    /search?q=test       → XSS, SQLi
SKIP      /static/style.css   → (skipped)
```

**4. Adaptive Payload Loop** — payloads refine based on response:
```
Attempt 1: <script>alert(1)</script>  → BLOCKED by WAF
Attempt 2: <ScRiPt>alert(1)</sCrIpT>  → HTTP 200, reflected ✓
```
Each attempt feeds back to LLM for WAF bypass techniques.

**5. Smart Memory** — learns across sessions:
- Jaccard similarity to find past targets with same tech stack
- Reuses payloads that worked on similar tech+vuln combos
- Cross-target learning: "WordPress 6.x → this XSS worked before"

---

## Multi-Agent Mode

```bash
argus agent example.com --multi-agent
```

Three specialized agents run sequentially, each with restricted skills:

| Agent | Skills | Focus |
|---|---|---|
| **Recon** | subfinder, httpx, katana, whatweb, naabu | Discovery: subdomains, ports, tech |
| **Vuln Scanner** | nuclei, check_headers, ffuf | Detection: known vulns, misconfigs |
| **Exploit** | dalfox, sqlmap, test_payload | Exploitation: XSS, SQLi, custom payloads |

Each agent has its own LLM decision loop. Results flow from Recon → Vuln Scanner → Exploit.

---

## Skill System

11 skills wrap existing tools with a uniform interface:

| Skill | Tool | What it does |
|---|---|---|
| `enumerate_subdomains` | subfinder | Find subdomains |
| `probe_http` | httpx | Check live hosts |
| `crawl_site` | katana | Discover all URLs |
| `scan_nuclei` | nuclei | Template-based vuln scanning |
| `fuzz_paths` | ffuf | Directory brute-force |
| `scan_xss` | dalfox | XSS (reflected, stored, DOM) |
| `scan_sqli` | sqlmap | SQL injection |
| `check_headers` | httpx | Security header analysis |
| `detect_tech` | whatweb | Technology fingerprinting |
| `scan_ports` | naabu | TCP port scanning |
| `test_payload` | httpx | Custom HTTP + reflection/error detection |

---

## Installation

### Kali Linux

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
sudo ./install.sh
```

### Docker

```bash
docker run -v ./reports:/reports ghcr.io/cortexc0de/argus-lite scan example.com --no-confirm
```

---

## Commands

### Agent (autonomous)
```bash
argus agent TARGET                   # autonomous single agent (plan tree + attack graph)
argus agent TARGET --multi-agent     # 3-agent team
argus agent TARGET --max-steps 15    # more iterations
```

### Scan (pipeline)
```bash
argus scan TARGET --preset full --ai   # full scan + AI analysis
argus scan TARGET --preset quick       # fast (DNS + headers + SSL)
argus scan TARGET --preset web         # web focus (httpx + nuclei + dalfox)
argus scan TARGET --no-cve             # skip CVE lookup
```

### Discover (find vulnerable hosts)
```bash
argus discover --cve CVE-2024-1234     # by CVE across Shodan/Censys/ZoomEye/FOFA
argus discover --tech "WordPress 6.3"  # by technology
argus discover --port 3389 --country RU
```

### Bulk (multi-target)
```bash
argus bulk targets.txt
argus bulk 192.168.1.0/24
argus bulk --shodan "org:Company"
argus bulk --censys "services.port:443"
argus bulk --zoomeye "app:nginx"
argus bulk --fofa 'domain="example.com"'
```

### Monitor (continuous)
```bash
argus monitor example.com --interval 24h --notify
```

### Dashboard
```bash
argus dashboard                        # http://127.0.0.1:8443
```

### Config
```bash
argus config ai                        # set AI provider
argus tools check                      # verify all tools
```

---

## Scan Pipeline (non-agent mode)

```
OSINT:    Shodan, Censys, ZoomEye, FOFA, GreyNoise, VirusTotal, SecurityTrails
  ↓
Recon:    subfinder, dnsx, httpx, katana, gau, tlsx, gowitness
  ↓
Analysis A: naabu (ports), whatweb (tech), headers, SSL
  ↓
Analysis B: nuclei, ffuf
  ↓
Analysis C: dalfox (XSS), sqlmap (SQLi)  ← gf patterns filter URLs first
  ↓
CVE Correlation (NVD API) → Correlation Engine → AI Analysis (with remediation)
  ↓
Report: HTML / JSON / Markdown / SARIF
```

---

## Web Dashboard

```bash
argus dashboard   # → http://127.0.0.1:8443
```

- **Dashboard** — stats, risk chart (Chart.js), scan history
- **New Scan** — launch from browser with htmx
- **OSINT** — search all APIs interactively
- **Settings** — API keys, AI, notifications, rate limits

REST API: `/api/scans`, `/api/scans/{id}`, `/api/compare?a={id}&b={id}`, `/api/stats`

---

## OSINT API Keys

```bash
export ARGUS_SHODAN_KEY="..."
export ARGUS_CENSYS_ID="..."
export ARGUS_CENSYS_SECRET="..."
export ARGUS_ZOOMEYE_KEY="..."
export ARGUS_FOFA_EMAIL="..."
export ARGUS_FOFA_KEY="..."
export ARGUS_GREYNOISE_KEY="..."   # optional — community tier is free
export ARGUS_VIRUSTOTAL_KEY="..."
export ARGUS_NVD_KEY="..."         # free, improves CVE rate limit
export ARGUS_AI_KEY="..."          # OpenAI / Ollama / vLLM / any compatible
```

Or configure via `argus config ai` or web Settings.

---

## GitHub Actions

```yaml
- uses: cortexc0de/argus-lite@v1
  with:
    target: ${{ vars.SCAN_TARGET }}
    preset: quick
    fail-on: HIGH
    output-format: sarif
```

---

## Version History

| Version | Highlights |
|---|---|
| **v4.0.0** | **Plan Trees** (branching), **Attack Graphs** (chains), **Adaptive Payloads** (WAF bypass loop), **Target Scoring**, **Multi-Agent** (3 specialized agents), Smart Memory (Jaccard similarity) |
| v3.0.0 | Closed execution loop — skills actually run, not just printed; AgentPlanner, SkillRegistry, AgentMemory |
| v2.0.0 | Agent mode (reactive), elite tools (Dalfox/SQLMap/Interactsh), JWT auth, threat intel |
| v1.8.0 | Web dashboard v2 (Flask + htmx, REST API, charts) |
| v1.6.0 | Continuous monitoring, enhanced AI (Russian, remediation commands) |
| v1.5.0 | Full TUI (5 tabs), vulnerability discovery engine |
| v1.3.0 | Censys, ZoomEye, FOFA, GreyNoise APIs |
| v1.2.0 | Bulk scanner (file/CIDR/ASN) |
| v1.1.0 | CVE correlation, YAML templates, GitHub Actions, Docker |
| v1.0.0 | Initial: 11 tools, 3 OSINT APIs, smart pipeline |

---

## Project Structure

```
src/argus_lite/
├── cli.py                      # All commands: agent, scan, bulk, discover, monitor...
├── core/
│   ├── agent.py                # PentestAgent (plan tree, attack graph, closed loop)
│   ├── agent_context.py        # PlanTree, PlanNode, AgentContext, AgentResult
│   ├── agent_memory.py         # SmartMemory (Jaccard similarity, cross-target learning)
│   ├── attack_graph.py         # AttackGraph (nodes, edges, exploit chains)
│   ├── payload_engine.py       # PayloadEngine (try → analyze → refine → retry)
│   ├── target_scorer.py        # TargetScorer (critical/high/medium/low/skip)
│   ├── multi_agent.py          # AgentTeam (Recon + Vuln Scanner + Exploit)
│   ├── skills.py               # Skill ABC + 11 implementations + SkillRegistry
│   ├── orchestrator.py         # ScanOrchestrator (presets, parallel pipeline)
│   ├── discovery_engine.py     # Vulnerability discovery across OSINT
│   ├── bulk_scanner.py         # Multi-target concurrency
│   ├── monitor.py              # Continuous monitoring with diff + notify
│   ├── ai_analyzer.py          # Post-scan AI (remediation commands, Russian)
│   ├── cve_enricher.py         # NVD API CVE correlation
│   ├── correlation.py          # Cross-reference OSINT + CVE + ports
│   └── config.py               # AppConfig (Pydantic v2)
├── modules/
│   ├── recon/                  # 10 recon modules + 7 OSINT APIs
│   └── analysis/               # nuclei, ports, tech, headers, ssl, ffuf,
│                               # dalfox, sqlmap, gf_patterns, interactsh
├── dashboard/                  # Flask + htmx web UI + JWT auth
└── models/                     # Pydantic models for all data
```

---

## License

MIT — see [LICENSE](LICENSE)
