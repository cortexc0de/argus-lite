# Argus Lite

Local CLI security scanner for authorized penetration testing on Kali Linux.

**Argus Lite automates common security reconnaissance and analysis tasks, aggregating results into a single structured report. It does NOT perform exploitation — detection only.**

## Legal Notice

```
This tool is intended for authorized security testing only.
Always obtain written permission before scanning any system you do not own.
Unauthorized scanning may violate computer crime laws in your jurisdiction.
The authors are not responsible for misuse of this tool.
```

## Features

- **Passive Recon** — DNS enumeration, WHOIS lookup, subdomain discovery, SSL certificate analysis
- **Active Analysis** — Port scanning (naabu), technology fingerprinting (whatweb), security headers check, SSL/TLS audit
- **Vulnerability Detection** — Nuclei integration (info/low severity only, enforced in code)
- **Reports** — JSON, Markdown, and HTML with severity color-coding
- **Safety First** — Input sanitization, command injection protection, scope validation (allowlist/denylist), rate limiting, audit logging

## Requirements

- **OS:** Kali Linux 2024+ (or Debian/Ubuntu)
- **Python:** 3.10+

### External Tools

| Tool | Purpose | Install |
|------|---------|---------|
| dig | DNS queries | `apt install dnsutils` (pre-installed on Kali) |
| whois | WHOIS lookup | `apt install whois` (pre-installed on Kali) |
| subfinder | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| naabu | Port scanning | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| whatweb | Technology fingerprinting | `apt install whatweb` |
| openssl | SSL/TLS checks | Pre-installed |

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd argus-lite

# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Initialize configuration
argus-lite init
```

## Usage

```bash
# Quick scan (passive recon + headers + tech stack)
argus-lite scan example.com --preset quick

# Full scan (all modules including nuclei)
argus-lite scan example.com --preset full --output html

# Recon only (no active scanning)
argus-lite scan example.com --preset recon --safe

# Skip confirmation prompt
argus-lite scan example.com --no-confirm

# Check available tools
argus-lite tools check

# View configuration
argus-lite config show

# List previous scans
argus-lite list
```

### Presets

| Preset | Duration | What it does |
|--------|----------|--------------|
| `quick` | 5-10 min | Passive recon, web headers, tech stack |
| `full` | 30-60 min | All modules including port scan and nuclei |
| `recon` | 5 min | DNS, WHOIS, subdomains only (passive) |
| `web` | 15-30 min | Web-focused: headers, tech, SSL, nuclei |

### Output Formats

```bash
--output json   # Machine-readable JSON
--output md     # Human-readable Markdown (default)
--output html   # Styled HTML with severity colors
```

Reports are saved to `~/.argus-lite/scans/<scan-id>/report/`.

## Configuration

Config file: `~/.argus-lite/config.yaml` (created by `argus-lite init` with `chmod 600`).

### API Keys

API keys can be set via environment variables (recommended) or in config:

```bash
export ARGUS_SHODAN_KEY="your-key"
export ARGUS_VIRUSTOTAL_KEY="your-key"
```

### Scope Control

```bash
# Allow only specific targets
echo "mysite.com" >> ~/.argus-lite/allowlist.txt

# Block specific targets
echo "google.com" >> ~/.argus-lite/denylist.txt
```

## Security Design

- **Input sanitization:** Strict regex validation, shell metacharacter rejection
- **Subprocess safety:** Never uses `shell=True`, arguments always passed as lists
- **Nuclei severity ceiling:** Hardcoded to `info/low` — medium/high/critical silently dropped even if returned
- **Rate limiting:** asyncio Semaphore + token bucket, configurable RPS
- **Audit logging:** All actions logged to JSON, API keys automatically masked
- **Scope enforcement:** Allowlist/denylist, private IP detection, confirmation prompts

## Architecture

```
CLI (Click) -> Input Sanitizer -> Orchestrator -> ToolRunner -> External Tools
                                      |
                                      v
                              Storage Layer -> Report Generator
```

### Module Structure

```
src/argus_lite/
├── cli.py                    # CLI entry point
├── core/                     # Orchestrator, config, validator, tool_runner, audit
├── models/                   # Pydantic data models
├── modules/
│   ├── recon/                # DNS, WHOIS, subdomains, certificates
│   ├── analysis/             # Ports, headers, tech stack, SSL, nuclei
│   └── report/               # JSON, Markdown, HTML generators
└── utils/                    # Progress tracking, logging
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=argus_lite --cov-report=term-missing

# Run specific module tests
python -m pytest tests/test_analysis/ -v
python -m pytest tests/test_recon/ -v
python -m pytest tests/test_report/ -v
```

**223 tests, 93%+ coverage.** All tests use fixture-based deterministic data — no network calls required.

## Development

Built with SDD (Specification-Driven Development) and TDD (Test-Driven Development):

1. Architecture spec written first (`architecture.md`)
2. Tests written before implementation (red-green-refactor)
3. Fixture-based testing with captured tool outputs

### Dependencies

- **click** — CLI framework
- **pydantic** — Data validation
- **rich** — Terminal UI, progress bars
- **httpx** — Async HTTP client
- **pyyaml** — Configuration
- **jinja2** — HTML report templating

## License

MIT
