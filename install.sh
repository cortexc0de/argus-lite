#!/usr/bin/env bash
set -euo pipefail

# Argus Lite — Installer for Kali Linux
# Usage: curl -sSL <repo>/install.sh | bash
#   or:  chmod +x install.sh && ./install.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="${ARGUS_DIR:-$HOME/argus-lite}"
REPO_URL="https://github.com/cortexc0de/argus-lite.git"

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

# --- Pre-checks ---

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        warn "Cannot detect OS. Continuing anyway..."
        return
    fi
    . /etc/os-release
    case "$ID" in
        kali|debian|ubuntu|parrot) ok "Detected OS: $PRETTY_NAME" ;;
        *) warn "Untested OS: $PRETTY_NAME. May still work." ;;
    esac
}

check_python() {
    if ! command -v python3 &>/dev/null; then
        fail "Python 3 not found. Install: sudo apt install python3 python3-venv"
    fi
    local ver
    ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if python3 -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)"; then
        ok "Python $ver"
    else
        fail "Python 3.10+ required, found $ver"
    fi
}

# --- System dependencies ---

install_apt_deps() {
    info "Installing system packages..."
    local pkgs=(dnsutils whois openssl curl whatweb git)
    local to_install=()

    for pkg in "${pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            ok "$pkg already installed"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        sudo apt update -qq
        sudo apt install -y -qq "${to_install[@]}"
        ok "Installed: ${to_install[*]}"
    fi
}

# --- Go + ProjectDiscovery tools ---

install_go() {
    if command -v go &>/dev/null; then
        ok "Go $(go version | grep -oP '\d+\.\d+\.\d+')"
        return
    fi
    info "Installing Go..."
    sudo apt install -y -qq golang
    ok "Go installed"
}

install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name already installed ($(which "$name"))"
        return
    fi
    info "Installing $name..."
    go install "$pkg" 2>&1 | tail -1 || true
    # Verify
    local gobin
    gobin="$(go env GOPATH)/bin"
    if [[ -x "$gobin/$name" ]]; then
        ok "$name installed -> $gobin/$name"
    else
        warn "$name installation may have failed. Check manually: go install $pkg"
    fi
}

setup_go_path() {
    local gobin
    gobin="$(go env GOPATH)/bin"
    if echo "$PATH" | grep -q "$gobin"; then
        return
    fi
    # Add to current session
    export PATH="$PATH:$gobin"
    # Persist in shell rc
    local rc="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" && ! -f "$HOME/.zshrc" ]] && rc="$HOME/.bashrc"
    if ! grep -q 'go env GOPATH' "$rc" 2>/dev/null; then
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> "$rc"
        ok "Added Go bin to PATH in $rc"
    fi
}

install_pd_tools() {
    install_go
    setup_go_path
    install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool naabu "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    install_go_tool nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        info "Updating nuclei templates..."
        nuclei -update-templates 2>&1 | tail -1 || true
        ok "Nuclei templates updated"
    fi
}

# --- Argus Lite ---

install_argus() {
    if [[ -d "$INSTALL_DIR" ]]; then
        info "Argus Lite directory exists, pulling latest..."
        cd "$INSTALL_DIR"
        git pull --ff-only 2>/dev/null || warn "Git pull failed, using existing code"
    else
        info "Cloning Argus Lite..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        ok "Cloned to $INSTALL_DIR"
    fi

    # Create venv
    if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
        info "Creating virtual environment..."
        python3 -m venv "$INSTALL_DIR/.venv"
    fi

    # Install
    info "Installing Python dependencies..."
    "$INSTALL_DIR/.venv/bin/pip" install -q -e ".[dev]"
    ok "Argus Lite installed"

    # Create shell alias
    local rc="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" && ! -f "$HOME/.zshrc" ]] && rc="$HOME/.bashrc"
    if ! grep -q 'alias argus-lite=' "$rc" 2>/dev/null; then
        echo "alias argus-lite='$INSTALL_DIR/.venv/bin/argus-lite'" >> "$rc"
        ok "Added alias 'argus-lite' to $rc"
    fi

    # Init config
    "$INSTALL_DIR/.venv/bin/argus-lite" init 2>/dev/null || true
}

# --- Naabu permissions ---

fix_naabu_caps() {
    local naabu_path
    naabu_path="$(which naabu 2>/dev/null || echo "$(go env GOPATH)/bin/naabu")"
    if [[ -x "$naabu_path" ]]; then
        info "Setting naabu network capabilities (needs sudo)..."
        sudo setcap cap_net_raw=ep "$naabu_path" 2>/dev/null && \
            ok "naabu can now scan without sudo" || \
            warn "Could not set capabilities. Run naabu with sudo if needed."
    fi
}

# --- Verify ---

verify_installation() {
    echo ""
    info "Verification:"
    echo ""
    "$INSTALL_DIR/.venv/bin/argus-lite" tools check
    echo ""
    "$INSTALL_DIR/.venv/bin/argus-lite" --version
    echo ""
}

# --- Main ---

main() {
    echo ""
    echo -e "${CYAN}=== Argus Lite Installer ===${NC}"
    echo ""

    check_os
    check_python
    install_apt_deps
    install_pd_tools
    install_argus
    fix_naabu_caps
    verify_installation

    echo -e "${GREEN}=== Installation complete ===${NC}"
    echo ""
    echo "  Reload your shell:    source ~/.zshrc"
    echo "  Quick scan:           argus-lite scan <target> --preset quick"
    echo "  Full scan:            argus-lite scan <target> --preset full --output html"
    echo "  Check tools:          argus-lite tools check"
    echo ""
}

main "$@"
