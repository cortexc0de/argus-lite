#!/usr/bin/env bash
set -euo pipefail

# Argus Lite — Installer for Kali Linux
# Downloads pre-built binaries (no Go compilation needed)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# If running from cloned repo, use that directory; otherwise default
if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    INSTALL_DIR="$SCRIPT_DIR"
else
    INSTALL_DIR="${ARGUS_DIR:-$HOME/argus-lite}"
fi
REPO_URL="https://github.com/cortexc0de/argus-lite.git"
BIN_DIR="/usr/local/bin"

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

run_with_spinner() {
    local msg="$1"; shift
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
        tail -5 "$logfile" 2>/dev/null | sed 's/^/    /'
        return 1
    fi
}

# Detect arch for binary downloads
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7*|armhf) echo "armv6" ;;
        *) echo "amd64" ;;
    esac
}

ARCH=$(detect_arch)
OS="linux"

# --- Pre-checks ---

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        ok "OS: $PRETTY_NAME ($ARCH)"
    else
        warn "Unknown OS ($ARCH)"
    fi
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

get_sudo() {
    if sudo -n true 2>/dev/null; then return; fi
    echo ""
    info "Some steps need sudo. Enter password:"
    sudo -v || fail "sudo required"
    echo ""
}

# --- System dependencies ---

wait_for_dpkg() {
    local tries=0
    while sudo fuser /var/lib/dpkg/lock-frontend &>/dev/null 2>&1; do
        if [[ $tries -eq 0 ]]; then
            info "Waiting for other apt/dpkg process to finish..."
        fi
        sleep 2
        tries=$((tries + 1))
        if [[ $tries -gt 30 ]]; then
            warn "dpkg lock held too long, skipping apt"
            return 1
        fi
    done
    return 0
}

install_apt_deps() {
    local pkgs=(dnsutils whois openssl curl whatweb git python3-venv libpcap-dev)
    local to_install=()

    for pkg in "${pkgs[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            ok "$pkg"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        wait_for_dpkg || return 0
        run_with_spinner "apt update" sudo apt update -y || true
        run_with_spinner "Installing ${to_install[*]}" \
            sudo apt install -y "${to_install[@]}" || \
            warn "Some packages failed"
    fi
}

# --- Download pre-built binaries ---

# Get latest release tag from GitHub API
get_latest_release() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | \
        grep -oP '"tag_name":\s*"\K[^"]+'
}

# Download and install a pre-built binary
install_binary() {
    local name="$1" repo="$2" url_pattern="$3"

    if command -v "$name" &>/dev/null; then
        ok "$name already installed ($(command -v "$name"))"
        return 0
    fi

    info "Downloading $name..."

    local version
    version=$(get_latest_release "$repo" 2>/dev/null) || {
        warn "Could not fetch latest $name version"
        return 0
    }

    # Strip leading 'v' for URL if needed
    local ver_stripped="${version#v}"

    # Build download URL from pattern
    local url
    url=$(echo "$url_pattern" | sed "s|{VERSION}|$version|g; s|{VER}|$ver_stripped|g; s|{OS}|$OS|g; s|{ARCH}|$ARCH|g")

    local tmpdir
    tmpdir=$(mktemp -d)

    if run_with_spinner "Downloading $name $version" curl -fsSL -o "$tmpdir/download" "$url"; then
        cd "$tmpdir"

        # Detect format and extract or use directly
        if [[ "$url" == *.zip ]]; then
            mv download archive.zip
            unzip -q archive.zip 2>/dev/null || true
        elif [[ "$url" == *.tar.gz || "$url" == *.tgz ]]; then
            mv download archive.tar.gz
            tar xzf archive.tar.gz 2>/dev/null || true
        else
            # Raw binary (e.g. gowitness) — rename directly
            mv download "$name"
        fi

        # Find and install binary
        local bin_file
        bin_file=$(find "$tmpdir" -name "$name" -type f 2>/dev/null | head -1)
        if [[ -z "$bin_file" ]]; then
            bin_file=$(find "$tmpdir" -name "$name*" -type f 2>/dev/null | head -1)
        fi

        if [[ -n "$bin_file" ]]; then
            chmod +x "$bin_file"
            sudo mv "$bin_file" "$BIN_DIR/$name"
            ok "$name $version -> $BIN_DIR/$name"
        else
            warn "$name binary not found in archive"
        fi
        cd - >/dev/null
    else
        warn "Failed to download $name"
    fi

    rm -rf "$tmpdir"
}

install_security_tools() {
    echo ""
    info "Downloading pre-built binaries (no compilation needed)..."
    echo ""

    install_binary "subfinder" \
        "projectdiscovery/subfinder" \
        "https://github.com/projectdiscovery/subfinder/releases/download/{VERSION}/subfinder_{VER}_{OS}_{ARCH}.zip"

    install_binary "naabu" \
        "projectdiscovery/naabu" \
        "https://github.com/projectdiscovery/naabu/releases/download/{VERSION}/naabu_{VER}_{OS}_{ARCH}.zip"

    install_binary "nuclei" \
        "projectdiscovery/nuclei" \
        "https://github.com/projectdiscovery/nuclei/releases/download/{VERSION}/nuclei_{VER}_{OS}_{ARCH}.zip"

    install_binary "httpx" \
        "projectdiscovery/httpx" \
        "https://github.com/projectdiscovery/httpx/releases/download/{VERSION}/httpx_{VER}_{OS}_{ARCH}.zip"

    install_binary "katana" \
        "projectdiscovery/katana" \
        "https://github.com/projectdiscovery/katana/releases/download/{VERSION}/katana_{VER}_{OS}_{ARCH}.zip"

    install_binary "dnsx" \
        "projectdiscovery/dnsx" \
        "https://github.com/projectdiscovery/dnsx/releases/download/{VERSION}/dnsx_{VER}_{OS}_{ARCH}.zip"

    install_binary "tlsx" \
        "projectdiscovery/tlsx" \
        "https://github.com/projectdiscovery/tlsx/releases/download/{VERSION}/tlsx_{VER}_{OS}_{ARCH}.zip"

    install_binary "gau" \
        "lc/gau" \
        "https://github.com/lc/gau/releases/download/{VERSION}/gau_{VER}_{OS}_{ARCH}.tar.gz"

    install_binary "ffuf" \
        "ffuf/ffuf" \
        "https://github.com/ffuf/ffuf/releases/download/{VERSION}/ffuf_{VER}_{OS}_{ARCH}.tar.gz"

    install_binary "gowitness" \
        "sensepost/gowitness" \
        "https://github.com/sensepost/gowitness/releases/download/{VERSION}/gowitness-{VER}-{OS}-{ARCH}"

    # Set naabu raw socket capability
    if [[ -x "$BIN_DIR/naabu" ]]; then
        sudo setcap cap_net_raw=ep "$BIN_DIR/naabu" 2>/dev/null && \
            ok "naabu: raw socket capability set" || true
    fi

    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        run_with_spinner "Updating nuclei templates" nuclei -update-templates || true
    fi
}

# --- Argus Lite ---

install_argus() {
    echo ""
    info "Installing Argus Lite..."

    # Detect the real user (even when running under sudo)
    local real_user="${SUDO_USER:-$(whoami)}"
    local real_home
    real_home=$(eval echo "~$real_user")

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Directory exists, pulling latest..."
        cd "$INSTALL_DIR"
        # Fix ownership if running as sudo
        if [[ -n "$SUDO_USER" ]]; then
            chown -R "$real_user:$real_user" "$INSTALL_DIR" 2>/dev/null || true
        fi
        sudo -u "$real_user" git pull --ff-only 2>/dev/null || warn "Git pull failed, using existing"
    else
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        run_with_spinner "Cloning repository" sudo -u "$real_user" git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
        run_with_spinner "Creating Python venv" sudo -u "$real_user" python3 -m venv "$INSTALL_DIR/.venv"
    fi

    # Fix ownership before pip install
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$real_user:$real_user" "$INSTALL_DIR" 2>/dev/null || true
    fi

    # Run pip as the real user (not root) to avoid permission issues
    run_with_spinner "Installing Python dependencies" \
        sudo -u "$real_user" "$INSTALL_DIR/.venv/bin/pip" install --no-input --force-reinstall --no-deps -e .
    sudo -u "$real_user" "$INSTALL_DIR/.venv/bin/pip" install --no-input -q -e ".[dev]" 2>/dev/null || true

    ok "Argus Lite installed"

    # Verify entry point was created
    if [[ ! -x "$INSTALL_DIR/.venv/bin/argus" ]]; then
        warn "Entry point not found, creating wrapper script..."
        cat > "$INSTALL_DIR/.venv/bin/argus" << 'WRAPPER'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/python" -m argus_lite.cli "$@"
WRAPPER
        chmod +x "$INSTALL_DIR/.venv/bin/argus"
    fi

    # Ensure entry points are executable
    chmod +x "$INSTALL_DIR/.venv/bin/argus" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/.venv/bin/argus-lite" 2>/dev/null || true

    # Symlink into /usr/local/bin so it works from anywhere
    sudo rm -f /usr/local/bin/argus /usr/local/bin/argus-lite 2>/dev/null
    sudo ln -sf "$INSTALL_DIR/.venv/bin/argus" /usr/local/bin/argus
    sudo ln -sf "$INSTALL_DIR/.venv/bin/argus-lite" /usr/local/bin/argus-lite

    # Verify it actually works
    if /usr/local/bin/argus --version &>/dev/null; then
        ok "Command 'argus' is ready (/usr/local/bin/argus)"
    else
        warn "Symlink failed. Use: $INSTALL_DIR/.venv/bin/argus"
    fi

    sudo -u "$real_user" "$INSTALL_DIR/.venv/bin/argus" init 2>/dev/null || true
    ok "Config: ~/.argus-lite/"
}

# --- Verify ---

verify() {
    echo ""
    echo -e "${BOLD}=== Tool Status ===${NC}"
    echo ""
    "$INSTALL_DIR/.venv/bin/argus" tools check 2>/dev/null || true
    echo ""
    "$INSTALL_DIR/.venv/bin/argus" --version 2>/dev/null || true
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
    echo "             |___/          Installer v1.1     "
    echo -e "${NC}"

    check_os
    check_python
    get_sudo

    echo ""
    echo -e "${BOLD}--- Step 1/4: System packages ---${NC}"
    install_apt_deps

    echo ""
    echo -e "${BOLD}--- Step 2/4: Security tools ---${NC}"
    install_security_tools

    echo ""
    echo -e "${BOLD}--- Step 3/4: Argus Lite ---${NC}"
    install_argus

    echo ""
    echo -e "${BOLD}--- Step 4/4: Verification ---${NC}"
    verify

    echo ""
    echo -e "${GREEN}${BOLD}=== Installation complete ===${NC}"
    echo ""
    echo "  Quick scan:     argus scan <target> --preset quick"
    echo "  Full scan:      argus scan <target> --preset full --output html"
    echo "  Check tools:    argus tools check"
    echo ""
}

main "$@"
