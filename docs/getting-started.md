# Getting Started

Get up and running with Argus in 5 minutes.

## Prerequisites

- **Kali Linux** (recommended) or any Debian-based Linux
- **Python 3.10+**
- **Go** (for tool compilation)

## Installation

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
sudo ./install.sh
```

This installs all 15 tools (subfinder, httpx, nuclei, etc.) and the Python package.

## Your First Scan

```bash
# Quick scan (DNS + headers + SSL)
argus scan example.com --preset quick

# Full scan (all tools)
argus scan example.com --preset full
```

## Your First Agent Run

```bash
# Set up AI provider
export ARGUS_AI_KEY="your-openai-key"

# Run the autonomous agent
argus agent example.com
```

The agent will:
1. Run quick recon to understand the target
2. Build an attack plan based on findings
3. Execute skills (nuclei, XSS, SQLi, etc.)
4. Adapt strategy based on results
5. Save findings and generate a report

## Next Steps

- [Installation Guide](installation.md) — Docker, manual setup, troubleshooting
- [Configuration](configuration.md) — API keys, presets, custom settings
- [Agent Guide](agent-guide.md) — missions, stealth, multi-agent mode
- [CLI Reference](cli-reference.md) — all commands and flags
