#!/usr/bin/env bash
set -euo pipefail

# Argus Lite — Installer for Kali Linux
# Usage: chmod +x install.sh && ./install.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="${ARGUS_DIR:-$HOME/argus-lite}"
REPO_URL="https://github.com/cortexc0de/argus-lite.git"

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Spinner for long-running commands
spin() {
    local pid=$1 msg=$2
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}[%s]${NC} %s" "${chars:i++%${#chars}:1}" "$msg"
        sleep 0.1
    done
    wait "$pid"
    return $?
}

# Run command with spinner (stdout/stderr to log file)
run_with_spinner() {
    local msg="$1"
    shift
    local logfile
    logfile=$(mktemp /tmp/argus-install-XXXXXX.log)

    "$@" >"$logfile" 2>&1 &
    local pid=$!

    if spin "$pid" "$msg"; then
        printf "\r${GREEN}[+]${NC} %-60s\n" "$msg"
        rm -f "$logfile"
        return 0
    else
        printf "\r${RED}[-]${NC} %-60s\n" "$msg — FAILED"
        echo -e "${YELLOW}    Log: $logfile${NC}"
        echo "    Last 5 lines:"
        tail -5 "$logfile" | sed 's/^/    /'
        return 1
    fi
}

# --- Pre-checks ---

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        warn "Cannot detect OS"
        return
    fi
    . /etc/os-release
    case "$ID" in
        kali|debian|ubuntu|parrot) ok "OS: $PRETTY_NAME" ;;
        *) warn "Untested OS: $PRETTY_NAME" ;;
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

# Ask for sudo password upfront so it doesn't block later
get_sudo() {
    if sudo -n true 2>/dev/null; then
        return
    fi
    echo ""
    info "Some steps need sudo. Enter your password now:"
    sudo -v || fail "sudo required"
    echo ""
}

# --- System dependencies ---

install_apt_deps() {
    local pkgs=(dnsutils whois openssl curl whatweb git python3-venv)
    local to_install=()

    for pkg in "${pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            ok "$pkg"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        run_with_spinner "apt update" sudo apt update -y || true
        run_with_spinner "Installing ${to_install[*]}" sudo apt install -y "${to_install[@]}" || \
            warn "Some packages failed to install"
    fi
}

# --- Go + ProjectDiscovery tools ---

install_go() {
    if command -v go &>/dev/null; then
        ok "Go $(go version | grep -oP '\d+\.\d+\.\d+' || echo 'found')"
        return
    fi
    run_with_spinner "Installing Go" sudo apt install -y golang || \
        fail "Could not install Go"
    ok "Go installed"
}

setup_go_path() {
    local gobin
    gobin="$(go env GOPATH 2>/dev/null)/bin"
    if [[ -z "$gobin" || "$gobin" == "/bin" ]]; then
        gobin="$HOME/go/bin"
    fi
    export PATH="$PATH:$gobin"

    local rc="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" && ! -f "$HOME/.zshrc" ]] && rc="$HOME/.bashrc"
    if ! grep -q 'go env GOPATH' "$rc" 2>/dev/null; then
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> "$rc"
        ok "Go PATH added to $rc"
    fi
}

install_go_tool() {
    local name="$1" pkg="$2"
    local gobin
    gobin="$(go env GOPATH 2>/dev/null)/bin"

    if command -v "$name" &>/dev/null || [[ -x "$gobin/$name" ]]; then
        ok "$name already installed"
        return
    fi

    run_with_spinner "Compiling $name (this takes a few minutes)" go install "$pkg" || {
        warn "$name failed to compile. Install manually: go install $pkg"
        return 0
    }

    if [[ -x "$gobin/$name" ]]; then
        ok "$name -> $gobin/$name"
    fi
}

install_pd_tools() {
    install_go
    setup_go_path

    echo ""
    info "Installing ProjectDiscovery tools (compiling from source)..."
    info "This can take 5-15 minutes total. Be patient."
    echo ""

    install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool naabu "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    install_go_tool nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        run_with_spinner "Updating nuclei templates" nuclei -update-templates || true
    fi
}

# --- Argus Lite ---

install_argus() {
    echo ""
    info "Installing Argus Lite..."

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Directory exists, pulling latest..."
        cd "$INSTALL_DIR"
        git pull --ff-only 2>/dev/null || warn "Git pull failed, using existing"
    else
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        run_with_spinner "Cloning repository" git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
        run_with_spinner "Creating Python venv" python3 -m venv "$INSTALL_DIR/.venv"
    fi

    run_with_spinner "Installing Python dependencies" \
        "$INSTALL_DIR/.venv/bin/pip" install --no-input -e ".[dev]"

    ok "Argus Lite installed"

    # Shell alias
    local rc="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" && ! -f "$HOME/.zshrc" ]] && rc="$HOME/.bashrc"
    if ! grep -q 'alias argus-lite=' "$rc" 2>/dev/null; then
        echo "alias argus-lite='$INSTALL_DIR/.venv/bin/argus-lite'" >> "$rc"
        ok "Alias 'argus-lite' added to $rc"
    fi

    # Init config
    "$INSTALL_DIR/.venv/bin/argus-lite" init 2>/dev/null || true
    ok "Config initialized at ~/.argus-lite/"
}

# --- Naabu permissions ---

fix_naabu_caps() {
    local naabu_path
    naabu_path="$(command -v naabu 2>/dev/null || echo "$(go env GOPATH 2>/dev/null)/bin/naabu")"
    if [[ -x "$naabu_path" ]]; then
        sudo setcap cap_net_raw=ep "$naabu_path" 2>/dev/null && \
            ok "naabu: raw socket capability set" || \
            warn "Could not set naabu capabilities (may need sudo for port scans)"
    fi
}

# --- Verify ---

verify() {
    echo ""
    echo -e "${BOLD}=== Tool Status ===${NC}"
    echo ""
    "$INSTALL_DIR/.venv/bin/argus-lite" tools check 2>/dev/null || true
    echo ""
    "$INSTALL_DIR/.venv/bin/argus-lite" --version 2>/dev/null || true
}

# --- Main ---

main() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "    _                          _     _ _       "
    echo "   / \   _ __ __ _ _   _ ___  | |   (_) |_ ___ "
    echo "  / _ \ | '__/ _\` | | | / __| | |   | | __/ _ \\"
    echo " / ___ \| | | (_| | |_| \__ \ | |___| | ||  __/"
    echo "/_/   \_\_|  \__, |\__,_|___/ |_____|_|\__\___|"
    echo "             |___/          Installer v1.0     "
    echo -e "${NC}"

    check_os
    check_python
    get_sudo

    echo ""
    echo -e "${BOLD}--- Step 1/4: System packages ---${NC}"
    install_apt_deps

    echo ""
    echo -e "${BOLD}--- Step 2/4: Security tools ---${NC}"
    install_pd_tools

    echo ""
    echo -e "${BOLD}--- Step 3/4: Argus Lite ---${NC}"
    install_argus
    fix_naabu_caps

    echo ""
    echo -e "${BOLD}--- Step 4/4: Verification ---${NC}"
    verify

    echo ""
    echo -e "${GREEN}${BOLD}=== Installation complete ===${NC}"
    echo ""
    echo "  1. Reload shell:   source ~/.zshrc"
    echo "  2. Quick scan:     argus-lite scan <target> --preset quick"
    echo "  3. Full scan:      argus-lite scan <target> --preset full --output html"
    echo ""
}

main "$@"
