# Installation

## Kali Linux (Recommended)

```bash
git clone https://github.com/cortexc0de/argus-lite.git
cd argus-lite
sudo ./install.sh
```

The installer will:
- Install system dependencies (Go, Python dev headers)
- Compile and install all 15 Go-based security tools
- Install the Python package with all dependencies
- Create default configuration at `~/.argus-lite/config.yaml`

## Docker

```bash
# Single scan
docker run -v ./reports:/reports ghcr.io/cortexc0de/argus-lite scan example.com

# With API keys
docker run \
  -e ARGUS_SHODAN_KEY="..." \
  -e ARGUS_AI_KEY="..." \
  -v ./reports:/reports \
  ghcr.io/cortexc0de/argus-lite agent example.com

# Docker Compose (includes dashboard)
docker-compose up
```

## Manual Installation

```bash
# 1. Install Python package
pip install -e .

# 2. Install Go tools manually
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/sensepost/gowitness@latest

# 3. Install dalfox and sqlmap
go install -v github.com/hahwul/dalfox/v2@latest
sudo apt install -y sqlmap

# 4. Verify tools
argus tools check
```

## Verifying Installation

```bash
# Check all tools are available
argus tools check

# Run a quick test
argus scan example.com --preset quick
```

## Troubleshooting

**Tools not found**: Ensure `~/go/bin` is in your `$PATH`:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

**Permission denied**: The installer needs `sudo` for system packages:
```bash
sudo ./install.sh
```

**Python version**: Argus requires Python 3.10+:
```bash
python3 --version  # Must be 3.10 or higher
```
