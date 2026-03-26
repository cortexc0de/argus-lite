<p align="center">
  <h1 align="center">ARGUS</h1>
  <p align="center">
    <strong>Autonomous AI pentesting framework for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#agent-mode">Agent Mode</a> •
    <a href="#commands">Commands</a> •
    <a href="#skill-system">Skills</a> •
    <a href="#web-dashboard">Dashboard</a> •
    <a href="#api">API</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-3.0.0-00ff41?style=flat-square" alt="Version">
    <img src="https://img.shields.io/badge/tests-647_passed-brightgreen?style=flat-square" alt="Tests">
    <img src="https://img.shields.io/badge/tools-15-orange?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/skills-11-ff6b6b?style=flat-square" alt="Skills">
    <img src="https://img.shields.io/badge/OSINT_APIs-7-blue?style=flat-square" alt="OSINT">
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  </p>
</p>

---

Argus is an **autonomous pentesting agent** where the LLM is the brain — it plans attacks, executes tools through a formal skill system, adapts strategy based on results, and remembers what worked across sessions.

```
LLM ≠ scanner.  LLM = brain.
Tools = hands.   Skills = actions.   Memory = experience.
```

> **Legal:** For authorized security testing only. Always obtain written permission.

---

## How It Works

```
┌─────────────────────────────────────┐
│          LLM Agent (brain)          │
│                                     │
│  1. Plan attack based on recon      │
│  2. Choose skill to execute         │
│  3. Receive result                  │
│  4. Adapt strategy                  │
│  5. Repeat until done               │
└──────────────┬──────────────────────┘
               │ decide → execute → feedback
┌──────────────▼──────────────────────┐
│     Skill System (11 skills)        │
│                                     │
│  enumerate_subdomains  probe_http   │
│  crawl_site   scan_nuclei           │
│  fuzz_paths   scan_xss (Dalfox)     │
│  scan_sqli (SQLMap)  scan_ports     │
│  check_headers  detect_tech         │
│  test_payload (custom HTTP)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     15 Tools + 7 OSINT APIs         │
│                                     │
│  subfinder httpx katana nuclei      │
│  naabu ffuf dalfox sqlmap           │
│  dnsx tlsx gau gowitness whatweb    │
│  interactsh gf-patterns             │
│                                     │
│  Shodan Censys ZoomEye FOFA         │
│  GreyNoise VirusTotal SecurityTrails│
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Memory + Reports                │
│                                     │
│  Persistent memory (JSON)           │
│  HTML / JSON / Markdown / SARIF     │
│  Web dashboard (Flask + htmx)       │
└─────────────────────────────────────┘
```

---

## Agent Mode

The core of Argus v3. The agent runs a **closed execution loop**:

```bash
argus agent example.com
```

```
AGENT MODE v3 — Autonomous pentesting with skill execution
Target: example.com | Max steps: 15

Phase 1: Quick recon scan
  ✓ recon
  ✓ analysis

Phase 2: LLM creates attack plan
  Goal: "Test API endpoints for IDOR and injection vulnerabilities"

Phase 3: Execute skills
  Step 1: "API has user ID parameter — testing for IDOR"
  → scan_sqli OK
  Found 2 injection points

  Step 2: "Checking for XSS in search parameter"
  → scan_xss OK
  Dalfox found 1 reflected XSS

  Step 3: "Testing custom payload with WAF bypass"
  → test_payload OK
  HTTP 200, payload reflected in response

  Step 4: "All high-priority vectors tested"
  → done
  Assessment complete: 3 vulnerabilities found

══════════════════════════════════════════════════
Agent complete
  Goal: Test API endpoints for IDOR and injection
  Steps: 4 | Skills: scan_sqli, scan_xss, test_payload
  Findings: 12
  Risk: HIGH
```

**What makes it autonomous:**
- **Plans before executing** — LLM builds goal-based attack plan from recon data
- **Executes skills** — actually runs tools, not just prints decisions
- **Feeds results back** — skill output goes into LLM context for next decision
- **Adapts on failure** — if a skill fails, LLM adjusts the plan
- **Remembers** — successful payloads and patterns saved to `~/.argus-lite/agent/memory.json`

---

## Skill System

11 skills wrapping existing tools with a uniform interface:

| Skill | Tool | What it does |
|---|---|---|
| `enumerate_subdomains` | subfinder | Find subdomains |
| `probe_http` | httpx | Check which hosts are alive |
| `crawl_site` | katana | Discover URLs and endpoints |
| `scan_nuclei` | nuclei | Vulnerability templates |
| `fuzz_paths` | ffuf | Directory brute-force |
| `scan_xss` | dalfox | XSS testing (reflected, stored, DOM) |
| `scan_sqli` | sqlmap | SQL injection testing |
| `check_headers` | httpx (Python) | Security header analysis |
| `detect_tech` | whatweb | Technology identification |
| `scan_ports` | naabu | TCP port scanning |
| `test_payload` | httpx (Python) | Custom HTTP request with payload + reflection detection |

Each skill: `execute(params, context) → SkillResult(success, data, findings, summary)`

The LLM chooses which skill to run based on context. Skills can be extended via the plugin system.

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
argus agent example.com                    # LLM-driven autonomous pentest
argus agent example.com --max-steps 15     # More iterations
```

### Scan (manual)
```bash
argus scan TARGET --preset full --ai       # Full scan + AI analysis
argus scan TARGET --preset quick           # Fast (DNS + headers + SSL)
argus scan TARGET --preset web             # Web focused (httpx + nuclei + dalfox)
argus scan TARGET --no-cve                 # Skip CVE lookup (faster)
```

### Discover (find vulnerable hosts)
```bash
argus discover --cve CVE-2024-1234         # By CVE
argus discover --tech "WordPress 6.3"      # By technology
argus discover --port 3389 --country RU    # By port + country
```

### Bulk (multi-target)
```bash
argus bulk targets.txt                     # From file
argus bulk 192.168.1.0/24                  # From CIDR
argus bulk --shodan "org:Company"          # From Shodan
argus bulk --censys "services.port:443"    # From Censys
argus bulk --zoomeye "app:nginx"           # From ZoomEye
argus bulk --fofa 'domain="example.com"'   # From FOFA
```

### Monitor (continuous)
```bash
argus monitor example.com --interval 24h --notify
```

### Dashboard (web UI)
```bash
argus dashboard                            # http://127.0.0.1:8443
```

### Config
```bash
argus config ai                            # Set up AI provider
argus config show                          # Show config
argus tools check                          # Verify tools
```

---

## Smart Pipeline

When not using agent mode, the standard scan pipeline:

```
OSINT (parallel): Shodan, Censys, ZoomEye, FOFA, GreyNoise, VT, ST
  ↓
Recon Group 1: DNS, WHOIS, subdomains, certificates
  ↓
Recon Group 2: httpx, katana, gau, dnsx, tlsx, gowitness
  ↓
Analysis A (parallel): ports, techstack, headers, SSL
  ↓
Analysis B (parallel): nuclei, ffuf
  ↓
Analysis C (parallel): dalfox (XSS), sqlmap (SQLi)
  ↓
CVE Correlation (NVD API) → Correlation Engine → AI Analysis
  ↓
Report (HTML / JSON / Markdown / SARIF)
```

Data flows between tools: subdomains→httpx, crawl→ffuf, gf→dalfox, tech tags→nuclei.

---

## Web Dashboard

```bash
argus dashboard   # → http://127.0.0.1:8443
```

Flask + htmx dark theme UI:
- **Dashboard** — stat cards, risk distribution chart (Chart.js), scan history
- **New Scan** — launch scans from browser, htmx live updates
- **OSINT** — search Shodan/Censys/ZoomEye/FOFA interactively
- **Settings** — API keys, AI config, notifications, rate limits
- **Reports** — click any scan to view full HTML report

REST API:
```
GET  /api/scans                    GET  /api/scans/{id}
GET  /api/scans/{id}/findings      GET  /api/compare?a={id}&b={id}
GET  /api/stats                    POST /api/scan/start
POST /api/discover
```

---

## OSINT API Keys

All optional. Configure via `argus config ai`, web Settings, or env vars:

```bash
export ARGUS_SHODAN_KEY="..."           # shodan.io
export ARGUS_CENSYS_ID="..."            # censys.io
export ARGUS_CENSYS_SECRET="..."        # censys.io
export ARGUS_ZOOMEYE_KEY="..."          # zoomeye.org
export ARGUS_FOFA_EMAIL="..."           # fofa.info
export ARGUS_FOFA_KEY="..."             # fofa.info
export ARGUS_GREYNOISE_KEY="..."        # greynoise.io (optional — community works free)
export ARGUS_VIRUSTOTAL_KEY="..."       # virustotal.com
export ARGUS_NVD_KEY="..."              # nvd.nist.gov (free, faster CVE lookups)
export ARGUS_AI_KEY="..."               # OpenAI / Ollama / vLLM / any compatible
```

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
| **v3.0.0** | **Autonomous Agent** — closed execution loop, 11 skills, attack planner, persistent memory |
| v2.0.0 | AI agent mode (reactive), JWT auth, threat intel, elite tools (Dalfox/SQLMap/Interactsh) |
| v1.8.0 | Web Dashboard v2 (Flask + htmx, REST API, Chart.js) |
| v1.7.0 | Correlation Engine, plugin integration into orchestrator |
| v1.6.0 | Continuous Monitoring, Enhanced AI (Russian, remediation commands) |
| v1.5.0 | Full TUI (5 tabs), Discovery Engine |
| v1.3.0 | Censys, ZoomEye, FOFA, GreyNoise APIs |
| v1.2.0 | Bulk Scanner (file/CIDR/ASN/Shodan) |
| v1.1.0 | CVE Correlation, YAML templates, GitHub Actions, Docker |
| v1.0.0 | Initial: 11 tools, 3 OSINT APIs, smart pipeline, AI analysis |

---

## Project Structure

```
src/argus_lite/
├── cli.py                        # All commands: agent, scan, bulk, discover, monitor, dashboard
├── core/
│   ├── agent.py                  # PentestAgent v3 + AgentPlanner (closed execution loop)
│   ├── skills.py                 # Skill ABC + 11 implementations + SkillRegistry
│   ├── agent_context.py          # AgentContext, AgentPlan, AgentStep, AgentResult
│   ├── agent_memory.py           # Persistent JSON memory across sessions
│   ├── orchestrator.py           # ScanOrchestrator (6 presets, smart pipeline)
│   ├── discovery_engine.py       # Vulnerability discovery across OSINT APIs
│   ├── bulk_scanner.py           # Multi-target with concurrency
│   ├── monitor.py                # Continuous monitoring with diff + notify
│   ├── ai_analyzer.py            # Post-scan AI analysis (remediation, Russian)
│   ├── cve_enricher.py           # NVD API v2.0 CVE correlation
│   ├── correlation.py            # Attack surface scoring engine
│   ├── config.py                 # AppConfig (Pydantic v2, YAML, env overrides)
│   └── threat_intel.py           # Recent CVE feed for your tech stack
├── modules/
│   ├── recon/                    # 10 recon + 7 OSINT API modules
│   ├── analysis/                 # nuclei, ports, techstack, headers, ssl, ffuf,
│   │                             # dalfox, sqlmap, gf_patterns, interactsh
│   └── report/                   # HTML, JSON, Markdown, SARIF, bulk summary
├── dashboard/
│   ├── app.py                    # Flask + htmx web UI
│   ├── auth.py                   # JWT authentication
│   └── templates/                # Dashboard, scan, OSINT, settings pages
└── models/                       # Pydantic models for all data structures
```

---

## License

MIT — see [LICENSE](LICENSE)
