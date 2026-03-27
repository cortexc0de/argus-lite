# Configuration

## Config File

Argus configuration lives at `~/.argus-lite/config.yaml`. Created automatically on first run.

```yaml
general:
  output_dir: ~/.argus-lite/scans
  verbose: false

rate_limits:
  global_rps: 50
  per_tool_rps: 20

tools:
  subfinder:
    enabled: true
    path: subfinder
  nuclei:
    enabled: true
    path: nuclei
    severity: info,low,medium,high,critical

ai:
  enabled: false
  base_url: https://api.openai.com/v1
  model: gpt-4o
  api_key: ""

skills:
  dirs:
    - ~/.argus-lite/skills

plugins:
  enabled: true
  plugin_dirs:
    - ~/.argus-lite/plugins
```

## API Keys

Set via environment variables or `argus config ai`:

| Variable | Service | Required |
|----------|---------|----------|
| `ARGUS_AI_KEY` | OpenAI / Ollama / vLLM | For agent mode |
| `ARGUS_SHODAN_KEY` | Shodan | Optional |
| `ARGUS_CENSYS_ID` | Censys API ID | Optional |
| `ARGUS_CENSYS_SECRET` | Censys API Secret | Optional |
| `ARGUS_ZOOMEYE_KEY` | ZoomEye | Optional |
| `ARGUS_FOFA_EMAIL` | FOFA Email | Optional |
| `ARGUS_FOFA_KEY` | FOFA API Key | Optional |
| `ARGUS_GREYNOISE_KEY` | GreyNoise | Optional (free community tier) |
| `ARGUS_VIRUSTOTAL_KEY` | VirusTotal | Optional |
| `ARGUS_NVD_KEY` | NVD (CVE database) | Optional (improves rate limit) |

## Scan Presets

| Preset | Recon Tools | Analysis Tools | Use Case |
|--------|-------------|----------------|----------|
| `quick` | dns, whois, certificates | headers, techstack, ssl | Fast assessment |
| `full` | All 10 recon tools | All 8 analysis tools | Comprehensive scan |
| `recon` | dns, whois, subdomains, certs, dnsx, tlsx, gau | None | Reconnaissance only |
| `web` | dns, certs, httpx, katana, screenshots | headers, ssl, tech, nuclei, dalfox | Web application focus |
| `bulk` | dns, httpx | techstack, headers, nuclei | Multi-target speed |

## AI Provider

Argus works with any OpenAI-compatible API:

```bash
# OpenAI
export ARGUS_AI_KEY="sk-..."

# Ollama (local)
argus config ai
# Set base_url to http://localhost:11434/v1

# vLLM / any compatible
# Set base_url to your endpoint
```
