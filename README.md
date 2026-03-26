<p align="center">
  <h1 align="center">ARGUS</h1>
  <p align="center">
    <strong>AI-driven autonomous security scanner for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#commands">Commands</a> •
    <a href="#features">Features</a> •
    <a href="#ai-agent">AI Agent</a> •
    <a href="#web-dashboard">Dashboard</a> •
    <a href="#api">API</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-2.0.0-00ff41?style=flat-square" alt="Version">
    <img src="https://img.shields.io/badge/tests-622_passed-brightgreen?style=flat-square" alt="Tests">
    <img src="https://img.shields.io/badge/tools-15-orange?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/OSINT_APIs-7-blue?style=flat-square" alt="OSINT">
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  </p>
</p>

---

Argus is an **AI-driven autonomous pentesting framework** that orchestrates 15 security tools + 7 OSINT APIs through an intelligent pipeline. The LLM acts as the brain — classifying endpoints, generating context-specific payloads, and deciding what to scan at each step.

```
Tools = recon, scanning, exploitation
LLM   = analysis, strategy, decisions
```

> **Legal:** For authorized security testing only. Always obtain written permission before scanning.

---

## Architecture

```
┌─────────────────────────────────┐
│          LLM Agent (brain)      │  argus agent TARGET
│  classify → strategize → decide │
└──────────────┬──────────────────┘
               │
┌──────────────▼──────────────────┐
│         Smart Pipeline          │
│                                 │
│  Recon ──────────────────────── │
│  │ OSINT: Shodan, Censys,      │
│  │   ZoomEye, FOFA, GreyNoise, │
│  │   VirusTotal, SecurityTrails │
│  │ Tools: subfinder, dnsx,      │
│  │   httpx, katana, gau, tlsx  │
│  ▼                              │
│  Analysis ──────────────────── │
│  │ Group A: naabu, whatweb,     │
│  │   security headers, SSL     │
│  │ Group B: nuclei, ffuf       │
│  │ Group C: dalfox (XSS),      │
│  │   sqlmap (SQLi)             │
│  ▼                              │
│  Enrichment ───────────────── │
│  │ CVE correlation (NVD API)   │
│  │ Correlation engine          │
│  │ AI analysis + remediation   │
│  ▼                              │
│  Report (HTML/JSON/MD/SARIF)   │
└─────────────────────────────────┘
```

---

## Features

| Category | Details |
|---|---|
| **15 Tools** | subfinder, naabu, nuclei, httpx, katana, dnsx, tlsx, whatweb, ffuf, gau, gowitness, dalfox (XSS), sqlmap (SQLi), interactsh (OAST), gf patterns |
| **7 OSINT APIs** | Shodan, VirusTotal, SecurityTrails, Censys, ZoomEye, FOFA, GreyNoise |
| **AI Agent** | LLM classifies endpoints, generates payloads, decides scan strategy |
| **Smart Pipeline** | Tools feed data to each other: subdomains→httpx→nuclei, crawl→ffuf, gf→dalfox |
| **CVE Correlation** | NVD API v2.0 maps detected technologies to known CVEs |
| **Correlation Engine** | Cross-references OSINT + ports + CVEs → attack surface score |
| **Vulnerability Discovery** | `argus discover` — find vulnerable hosts across all OSINT APIs |
| **Bulk Scanner** | File lists, CIDR, ASN, Shodan/Censys/ZoomEye/FOFA queries |
| **Continuous Monitoring** | `argus monitor` — scheduled scans with diff notifications |
| **Web Dashboard** | Flask + htmx: dark theme, charts, scan history, OSINT queries, settings |
| **5 Report Formats** | HTML (dark theme), JSON, Markdown, SARIF (CI/CD), Bulk summary |
| **GitHub Actions** | `uses: cortexc0de/argus-lite@v1` — CI security gate with SARIF upload |
| **Docker** | `docker run ghcr.io/cortexc0de/argus-lite scan TARGET` |
| **AI Remediation** | Auto-generates Nginx/Apache/iptables configs to fix findings |
| **Multi-language AI** | English and Russian analysis (`ai.language: ru`) |
| **JWT Auth** | Dashboard authentication with role-based access |
| **Threat Intel** | Fetches recent CVEs for your tech stack from NVD |
| **Plugin System** | ABC plugin interface integrated into orchestrator pipeline |
| **622 Tests** | Full TDD/SDD coverage, all passing |

---

## Installation

### Kali Linux (recommended)

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
sudo ./install.sh
```

The installer downloads all 15 security tools, sets up Python venv, and creates the `argus` command.

### Docker

```bash
docker run -v ./reports:/reports ghcr.io/cortexc0de/argus-lite scan example.com --no-confirm
```

### Docker Compose

```bash
# Scan
TARGET=example.com docker compose run --rm scan

# Dashboard
docker compose up dashboard
# → http://localhost:8443
```

---

## Commands

### Core

```bash
argus                                    # Launch web dashboard
argus scan TARGET --preset full --ai     # Full scan with AI analysis
argus scan TARGET --preset quick         # Fast scan (DNS + headers + SSL)
argus scan TARGET --no-cve               # Skip CVE lookup (faster)
```

### AI Agent (autonomous pentesting)

```bash
argus agent example.com                  # LLM-driven scan
argus agent example.com --max-steps 15   # More decision iterations
```

### Vulnerability Discovery

```bash
argus discover --cve CVE-2024-1234       # Find vulnerable hosts by CVE
argus discover --tech "WordPress 6.3"    # Find hosts by technology
argus discover --port 3389 --country RU  # Open RDP in Russia
argus discover --service openssh         # Find SSH servers
```

### Bulk Scanning

```bash
argus bulk targets.txt                   # From file
argus bulk 192.168.1.0/24               # From CIDR
argus bulk AS12345                       # From ASN
argus bulk --shodan "org:Company"        # From Shodan query
argus bulk --censys "services.port:443"  # From Censys
argus bulk --zoomeye "app:nginx"         # From ZoomEye
argus bulk --fofa 'domain="example.com"' # From FOFA
```

### Continuous Monitoring

```bash
argus monitor example.com --interval 24h --notify
argus monitor target.com --interval 1h --preset web --max-runs 10
```

### Configuration

```bash
argus config ai                          # Set up AI provider (interactive)
argus config show                        # Show current config
argus dashboard                          # Launch web UI
argus tools check                        # Verify tool availability
```

### Scan Templates

```bash
argus run examples/quick_scan.yaml --target example.com
TARGET=mysite.com argus run examples/full_scan.yaml
```

---

## AI Agent

The agent mode (`argus agent`) turns Argus into an **autonomous pentesting system**:

```
Phase 1: Collect intelligence (full scan)
Phase 2: AI classifies endpoints
  HIGH  /api/user?id=123 → IDOR, SQLi
  HIGH  /redirect?url=   → SSRF, Open Redirect
  MED   /search?q=test   → XSS
Phase 3: Agent decision loop
  Step 1: "API has ID param → testing IDOR"    → scan_sqli
  Step 2: "Found SQL error → escalating"       → generate_payload
  Step 3: "Testing WAF bypass payload"         → test_payload
  Step 4: "All high-priority done"             → done
```

The LLM serves 4 roles:
- **Analyzer** — classifies endpoints, identifies tech stack
- **Strategist** — prioritizes attack vectors
- **Payload Generator** — context-specific payloads with WAF bypass
- **Loop Controller** — decides what to scan next

Requires an OpenAI-compatible API:
```bash
argus config ai
# → Base URL: https://api.openai.com/v1 (or Ollama, vLLM, etc.)
# → API Key: sk-xxx
# → Model: gpt-4o
```

---

## Web Dashboard

```bash
argus dashboard
# → http://127.0.0.1:8443
```

- **Dashboard** — stat cards, risk distribution chart, scan history
- **New Scan** — start scans from browser (htmx, no page reload)
- **OSINT** — search Shodan/Censys/ZoomEye/FOFA from browser
- **Settings** — API keys, AI config, notifications, rate limits
- **Reports** — click any scan to view HTML report

REST API:
```
GET  /api/scans                  — list all scans
GET  /api/scans/{id}             — scan detail
GET  /api/scans/{id}/findings    — findings for scan
GET  /api/compare?a={id}&b={id}  — diff two scans
GET  /api/stats                  — aggregate stats
POST /api/scan/start             — trigger scan (htmx)
POST /api/discover               — OSINT search (htmx)
```

---

## OSINT API Keys

All optional. Set via `argus config ai` (web Settings tab) or env vars:

```bash
export ARGUS_SHODAN_KEY="..."         # shodan.io
export ARGUS_CENSYS_ID="..."          # censys.io (API ID)
export ARGUS_CENSYS_SECRET="..."      # censys.io (API Secret)
export ARGUS_ZOOMEYE_KEY="..."        # zoomeye.org
export ARGUS_FOFA_EMAIL="..."         # fofa.info
export ARGUS_FOFA_KEY="..."           # fofa.info
export ARGUS_GREYNOISE_KEY="..."      # greynoise.io (optional, community works without)
export ARGUS_VIRUSTOTAL_KEY="..."     # virustotal.com
export ARGUS_NVD_KEY="..."            # nvd.nist.gov (free, increases rate limit)
export ARGUS_AI_KEY="..."             # OpenAI-compatible provider
```

---

## Scan Presets

| Preset | Recon | Analysis | Use case |
|---|---|---|---|
| `quick` | DNS, WHOIS, certificates | headers, techstack, SSL | Fast check |
| `full` | All 10 recon tools | All analysis + dalfox + sqlmap | Complete pentest |
| `web` | DNS, httpx, katana, screenshots | headers, SSL, techstack, nuclei, dalfox | Web applications |
| `recon` | DNS, subdomains, dnsx, tlsx, gau | None | Passive recon only |
| `bulk` | DNS, httpx | techstack, headers, nuclei | Fast per-host in bulk |

---

## GitHub Actions

```yaml
- uses: cortexc0de/argus-lite@v1
  with:
    target: ${{ vars.SCAN_TARGET }}
    preset: quick
    fail-on: HIGH             # Fail CI if risk >= HIGH
    output-format: sarif      # Auto-uploads to Security tab
    nvd-api-key: ${{ secrets.NVD_API_KEY }}
```

---

## Version History

| Version | Release | Highlights |
|---|---|---|
| **v2.0.0** | Current | AI Agent mode, JWT auth, threat intel feed |
| v1.8.0 | | Web Dashboard v2 (Flask + htmx, REST API, charts) |
| v1.7.0 | | Correlation Engine, plugin integration |
| v1.6.0 | | Continuous Monitoring, Enhanced AI (Russian, remediation) |
| v1.5.0 | | Full TUI (5 tabs), Discovery Engine |
| v1.4.0 | | `argus discover` — vulnerability discovery across OSINT |
| v1.3.0 | | Censys, ZoomEye, FOFA, GreyNoise OSINT APIs |
| v1.2.0 | | Bulk Scanner (file/CIDR/ASN), target expander |
| v1.1.0 | | CVE Correlation, TUI, YAML templates, GitHub Actions, Docker |
| v1.0.0 | | Initial: 11 tools, Shodan/VT/ST, AI analysis, smart pipeline |

---

## Project Structure

```
src/argus_lite/
├── cli.py                    # CLI entry (scan, bulk, discover, agent, monitor, dashboard)
├── core/
│   ├── orchestrator.py       # ScanOrchestrator (presets, parallel groups, smart pipeline)
│   ├── agent.py              # PentestAgent (LLM-driven autonomous scanning)
│   ├── discovery_engine.py   # Vulnerability discovery across OSINT APIs
│   ├── bulk_scanner.py       # Multi-target scanning with concurrency
│   ├── monitor.py            # Continuous monitoring with diff + notify
│   ├── ai_analyzer.py        # AI analysis (remediation commands, Russian support)
│   ├── cve_enricher.py       # NVD API v2.0 CVE correlation
│   ├── correlation.py        # Cross-reference OSINT + CVE + ports → attack surface
│   ├── config.py             # AppConfig (Pydantic v2, YAML, env overrides)
│   ├── threat_intel.py       # Threat intelligence feed (recent CVEs for your stack)
│   └── tool_runner.py        # Safe subprocess execution (never shell=True)
├── modules/
│   ├── recon/                # 10 recon modules + 7 OSINT API integrations
│   ├── analysis/             # nuclei, ports, techstack, headers, ssl, ffuf, dalfox, sqlmap, gf, interactsh
│   └── report/               # HTML, JSON, Markdown, SARIF, bulk summary
├── dashboard/
│   ├── app.py                # Flask + htmx web interface
│   ├── auth.py               # JWT authentication (HS256)
│   └── templates/            # base, dashboard, scan, osint, settings
├── tui/                      # Textual TUI (5 tabs)
└── models/                   # Pydantic models (scan, finding, recon, analysis, ai, bulk, monitor, discover)
```

---

## Contributing

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE)
