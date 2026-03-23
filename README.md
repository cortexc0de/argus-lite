<p align="center">
  <h1 align="center">ARGUS</h1>
  <p align="center">
    <strong>AI-powered security scanner for Kali Linux</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#features">Features</a> •
    <a href="#ai-analysis">AI Analysis</a> •
    <a href="#dashboard">Dashboard</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/tests-411_passed-brightgreen" alt="Tests">
    <img src="https://img.shields.io/badge/coverage-84%25-green" alt="Coverage">
    <img src="https://img.shields.io/badge/tools-14-orange" alt="Tools">
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  </p>
</p>

---

Argus is a local CLI security scanner that automates reconnaissance and analysis for authorized penetration testing. It orchestrates 11 CLI tools + 3 OSINT APIs, uses a **smart pipeline** where tools feed data to each other, and optionally applies **AI analysis** to produce actionable intelligence.

> **Detection only.** Argus does NOT perform exploitation. Nuclei severity is hardcoded to info/low — medium/high/critical findings are silently dropped in code.

## Features

| Category | What it does |
|----------|-------------|
| **Passive Recon** | DNS, WHOIS, subdomain discovery, certificate transparency, historical URLs (Wayback Machine) |
| **Active Analysis** | Port scanning, technology fingerprinting, security headers, SSL/TLS audit, directory fuzzing |
| **Vulnerability Detection** | Nuclei with 7000+ templates (info/low only), tech-specific template targeting |
| **OSINT APIs** | Shodan, VirusTotal, SecurityTrails — passive intel without active scanning |
| **AI Analysis** | LLM-powered executive summary, attack chains, prioritized findings, recommendations |
| **Smart Pipeline** | Subdomains → httpx → nuclei chain; crawled paths → ffuf seeds; tech → template tags |
| **Screenshots** | Automated web page screenshots via gowitness |
| **Reports** | JSON, Markdown, HTML (dark theme), SARIF (CI/CD) |
| **Dashboard** | Local web UI to browse all scans and reports |
| **Notifications** | Telegram, Discord, Slack alerts after scan |
| **Risk Scoring** | Automatic NONE/LOW/MEDIUM/HIGH assessment |
| **Plugin System** | Drop-in Python plugins in `~/.argus-lite/plugins/` |

### Security by Design

- **Input sanitization** — strict regex, shell metacharacter rejection
- **Subprocess safety** — never `shell=True`, arguments always as lists
- **Nuclei severity ceiling** — enforced in code, not just config
- **Rate limiting** — asyncio Semaphore + token bucket
- **Audit logging** — JSON log with automatic secret masking
- **Scope enforcement** — allowlist/denylist, private IP detection

## Installation

### One-line install (Kali Linux)

```bash
git clone https://github.com/cortexc0de/argus-lite.git ~/argus-lite
cd ~/argus-lite && sudo ./install.sh
```

The installer automatically:
- Downloads pre-built binaries (subfinder, naabu, nuclei, httpx, katana, dnsx, tlsx, gau, ffuf, gowitness)
- Creates Python venv and installs dependencies
- Sets up `argus` command globally
- Initializes config at `~/.argus-lite/`

### Manual install

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
argus init
```

## Usage

```bash
# Quick scan (DNS + headers + tech stack)
argus scan example.com --preset quick

# Full scan (all 11 tools + smart pipeline)
argus scan example.com --preset full --output html

# Full scan with AI analysis
argus scan example.com --preset full --output html --ai

# Recon only (passive, no active scanning)
argus scan example.com --preset recon

# Web-focused scan
argus scan example.com --preset web

# Resume interrupted scan
argus scan example.com --resume <scan-id>

# Custom nuclei templates
argus scan example.com --templates ~/my-templates/

# With notifications
argus scan example.com --preset full --notify

# SARIF output for CI/CD
argus scan example.com --output sarif
```

### Presets

| Preset | Tools | Duration |
|--------|-------|----------|
| `quick` | dig, whois, openssl, headers, whatweb, ssl | 5-10 min |
| `full` | All 11 tools + screenshots + OSINT APIs | 30-60 min |
| `recon` | dig, whois, subfinder, openssl, dnsx, tlsx, gau | 5-15 min |
| `web` | dig, openssl, httpx, katana, screenshots, headers, ssl, whatweb, nuclei | 15-30 min |

### Smart Pipeline

Tools automatically feed data to each other:

```
subfinder → finds 10 subdomains
    ↓
httpx → probes ALL 10 subdomains (not just main target)
    ↓
nuclei → scans ALL live hosts with tech-specific templates
    ↓
whatweb detects WordPress → nuclei uses -tags wordpress
    ↓
katana crawls /api/v1, /admin → ffuf uses these as seed wordlist
```

## AI Analysis

Argus supports any **OpenAI-compatible API** — OpenAI, Ollama, LM Studio, vLLM, Together AI, etc.

```bash
# Set your API endpoint
export ARGUS_AI_KEY="sk-your-key"
export ARGUS_AI_URL="https://api.openai.com/v1"    # or http://localhost:11434/v1
export ARGUS_AI_MODEL="gpt-4o"                      # or llama3, mistral, etc.

# Run with AI
argus scan example.com --preset full --output html --ai
```

AI generates:
- **Executive Summary** — 3-5 sentence security posture overview
- **Attack Chains** — realistic multi-step attack scenarios from findings
- **Prioritized Findings** — re-ranked by real exploitability
- **Recommendations** — specific to the target's tech stack
- **Trend Analysis** — changes compared to previous scan

## Dashboard

```bash
argus dashboard                          # http://127.0.0.1:8443
argus dashboard --port 9090              # custom port
argus dashboard --host 0.0.0.0           # network access
```

Browse all scans, click to view HTML reports with dark theme.

## OSINT API Keys

```bash
export ARGUS_SHODAN_KEY="your-key"           # Shodan host lookup
export ARGUS_VIRUSTOTAL_KEY="your-key"       # VirusTotal domain intel
export ARGUS_SECURITYTRAILS_KEY="your-key"   # SecurityTrails DNS/subdomain data
```

## Configuration

```bash
argus init              # Create ~/.argus-lite/config.yaml (chmod 600)
argus config show       # View current config
argus tools check       # Verify all tools installed
argus plugins list      # List installed plugins
```

### Scope Control

```bash
echo "mysite.com" >> ~/.argus-lite/allowlist.txt    # Allow specific targets
echo "google.com" >> ~/.argus-lite/denylist.txt     # Block specific targets
```

### Notifications

```bash
export ARGUS_TELEGRAM_TOKEN="bot-token"
export ARGUS_TELEGRAM_CHAT_ID="chat-id"
export ARGUS_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export ARGUS_SLACK_WEBHOOK="https://hooks.slack.com/..."
```

## Tools

| Tool | Purpose | Source |
|------|---------|--------|
| subfinder | Subdomain discovery | ProjectDiscovery |
| naabu | Port scanning | ProjectDiscovery |
| nuclei | Vulnerability scanning | ProjectDiscovery |
| httpx | HTTP probing | ProjectDiscovery |
| katana | Web crawling | ProjectDiscovery |
| dnsx | DNS resolution | ProjectDiscovery |
| tlsx | TLS cert analysis | ProjectDiscovery |
| whatweb | Tech fingerprinting | WhatWeb |
| ffuf | Directory fuzzing | ffuf |
| gau | Historical URLs | lc/gau |
| gowitness | Screenshots | SensePost |

## Architecture

```
CLI (Click)
 ↓
Input Sanitizer → Scope Validator
 ↓
Orchestrator (preset-driven, parallel execution)
 ├── Group 0: OSINT APIs (Shodan, VT, ST)
 ├── Group 1: Passive Recon (dig, whois, subfinder, openssl)
 ├── Group 2: Discovery (httpx→all subdomains, katana, gau, dnsx, tlsx, screenshots)
 ├── Group A: Analysis (naabu, whatweb, headers, ssl)
 └── Group B: Smart Analysis (nuclei→all live hosts+tech tags, ffuf→crawl seeds)
 ↓
Risk Scorer → AI Analyzer (optional)
 ↓
Report Generator (JSON/MD/HTML/SARIF) → Notifications → Dashboard
```

```
src/argus_lite/
├── cli.py                     # CLI entry point (Click)
├── core/
│   ├── orchestrator.py        # Scan coordinator + smart pipeline
│   ├── ai_analyzer.py         # LLM-powered analysis
│   ├── config.py              # Pydantic config + env overrides
│   ├── validator.py           # Input sanitization + scope
│   ├── tool_runner.py         # Safe subprocess abstraction
│   ├── risk_scorer.py         # Automatic risk scoring
│   ├── concurrent.py          # asyncio.gather with error isolation
│   ├── resume.py              # Partial scan save/load
│   ├── incremental.py         # Scan diff engine
│   ├── notifier.py            # Telegram/Discord/Slack
│   ├── plugin.py              # Plugin ABC
│   └── plugin_loader.py       # Auto-discovery of plugins
├── models/                    # Pydantic data models
├── modules/
│   ├── recon/                 # 11 recon modules
│   ├── analysis/              # 6 analysis modules
│   └── report/                # 5 report generators
├── dashboard/                 # Flask web UI
└── pipelines/                 # YAML pipeline definitions
```

## Testing

```bash
source .venv/bin/activate
python -m pytest tests/ -v                                    # All tests
python -m pytest tests/ --cov=argus_lite --cov-report=html    # Coverage report
python -m pytest tests/test_ai_analyzer.py -v                 # AI tests only
```

**411 tests, 84% coverage.** All tests use fixture-based deterministic data — zero network calls.

## Development

Built with **SDD** (Specification-Driven Development) and **TDD** (Test-Driven Development).

### Plugin Development

```python
# ~/.argus-lite/plugins/my_scanner.py
from argus_lite.core.plugin import ArgusPlugin

class MyScanner(ArgusPlugin):
    @property
    def name(self) -> str: return "my_scanner"

    @property
    def stage(self) -> str: return "recon"

    def check_available(self) -> bool: return True

    async def run(self, context: dict, config) -> None:
        context["my_scanner"] = {"custom": "data"}
```

## Legal Notice

```
This tool is intended for authorized security testing only.
Always obtain written permission before scanning any system you do not own.
Unauthorized scanning may violate computer crime laws in your jurisdiction.
The authors are not responsible for misuse of this tool.
```

## License

MIT
