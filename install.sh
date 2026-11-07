#!/usr/bin/env bash
# ==============================================================================
# sonus-rs: Sub-250ms PipeWire to Apple AirPlay 2 / RAOP Audio Engine Installer
# Works seamlessly on Arch Linux, Fedora, Ubuntu/Debian, and openSUSE.
# ==============================================================================
set -euo pipefail

# Visual formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
PIPEWIRE_CONF_DIR="${HOME}/.config/pipewire/pipewire.conf.d"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"

ENABLE_SERVICE=false
NO_BUILD=false

print_usage() {
    echo -e "${BOLD}Usage:${NC} $(basename "$0") [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${CYAN}--enable${NC}          Automatically stop legacy Python audio service (homelab-homepod-audio)"
    echo -e "                    and enable + start the production sonus.service systemd unit."
    echo -e "  ${CYAN}--no-build${NC}        Skip compilation and use existing target/release/sonus binary."
    echo -e "  ${CYAN}-h, --help${NC}        Show this help message and exit."
    echo ""
    echo -e "${BOLD}Installation Artifacts:${NC}"
    echo -e "  • Binary:         ~/.local/bin/sonus"
    echo -e "  • PipeWire Sink:  ~/.config/pipewire/pipewire.conf.d/60-homepod.conf"
    echo -e "  • Systemd Unit:   ~/.config/systemd/user/sonus.service"
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enable)
            ENABLE_SERVICE=true
            shift
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

echo -e "${CYAN}${BOLD}==> sonus-rs Installer: Sub-250ms AirPlay 2 Engine & Touch Daemon${NC}"

# ------------------------------------------------------------------------------
# Step 1: Binary Build / Location
# ------------------------------------------------------------------------------
TARGET_BIN=""
if [ -f "${SCRIPT_DIR}/target/release/sonus" ]; then
    TARGET_BIN="${SCRIPT_DIR}/target/release/sonus"
elif [ -f "${SCRIPT_DIR}/target/release/sonus-rs" ]; then
    TARGET_BIN="${SCRIPT_DIR}/target/release/sonus-rs"
fi

if [ -z "$TARGET_BIN" ] || [ "$NO_BUILD" = false ]; then
    if [ "$NO_BUILD" = true ] && [ -n "$TARGET_BIN" ]; then
        echo -e "${CYAN}[*] Using existing prebuilt binary: ${TARGET_BIN}${NC}"
    else
        echo -e "${CYAN}[*] Compiling optimized release binary with Cargo...${NC}"
        if ! command -v cargo >/dev/null 2>&1; then
            echo -e "${RED}[ERROR] 'cargo' is not installed or not in PATH.${NC}"
            echo -e "Please install Rust (https://rustup.rs) or run with --no-build if using a prebuilt binary."
            exit 1
        fi
        (cd "$SCRIPT_DIR" && cargo build --release)
        if [ -f "${SCRIPT_DIR}/target/release/sonus" ]; then
            TARGET_BIN="${SCRIPT_DIR}/target/release/sonus"
        elif [ -f "${SCRIPT_DIR}/target/release/sonus-rs" ]; then
            TARGET_BIN="${SCRIPT_DIR}/target/release/sonus-rs"
        fi
    fi
fi

if [ -z "$TARGET_BIN" ] || [ ! -f "$TARGET_BIN" ]; then
    echo -e "${RED}[ERROR] Could not locate compiled binary in target/release/.${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# Step 2: Install Binary to ~/.local/bin/sonus
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Installing binary to ${BIN_DIR}/sonus...${NC}"
mkdir -p "$BIN_DIR"
install -m 755 "$TARGET_BIN" "${BIN_DIR}/sonus"
echo -e "${GREEN}[✓] Installed ${BIN_DIR}/sonus${NC}"

if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo -e "${YELLOW}[!] Note: ${BIN_DIR} is not in your current PATH.${NC}"
    echo -e "    Add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your ~/.bashrc or ~/.zshrc."
fi

# ------------------------------------------------------------------------------
# Step 3: Install PipeWire Drop-in Configuration & Live Parameter Tuning
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Installing PipeWire configuration...${NC}"
mkdir -p "$PIPEWIRE_CONF_DIR"
cp -f "${SCRIPT_DIR}/pipewire/60-homepod.conf" "${PIPEWIRE_CONF_DIR}/60-homepod.conf"
echo -e "${GREEN}[✓] Installed ${PIPEWIRE_CONF_DIR}/60-homepod.conf${NC}"

# Apply live parameters via pw-cli if PipeWire and the HomePod sink are running
if command -v pw-cli >/dev/null 2>&1; then
    NODE_ID=""
    # Method 1: jq with pw-dump
    if command -v pw-dump >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        NODE_ID=$(pw-dump Node 2>/dev/null | jq -r '.[] | select(.info.props."node.name" == "HomePod") | .id' 2>/dev/null | head -n1 || true)
    fi
    # Method 2: python3 with pw-dump
    if [ -z "$NODE_ID" ] && command -v pw-dump >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        NODE_ID=$(pw-dump Node 2>/dev/null | python3 -c "import sys, json; nodes = json.load(sys.stdin); print(next((str(n.get('id','')) for n in nodes if n.get('info', {}).get('props', {}).get('node.name') == 'HomePod'), ''))" 2>/dev/null || true)
    fi
    # Method 3: awk with pw-cli list-objects
    if [ -z "$NODE_ID" ]; then
        NODE_ID=$(pw-cli list-objects Node 2>/dev/null | awk '/^[ \t]*id [0-9]+/ { id=$2; gsub(/,/, "", id) } /node\.name = "HomePod"/ { print id }' | head -n1 || true)
    fi

    if [ -n "$NODE_ID" ]; then
        echo -e "${CYAN}[*] Applying live PipeWire parameters to active HomePod sink (Node ID #${NODE_ID})...${NC}"
        # Inject 250ms ProcessLatency (rate: 11025 @ 44.1kHz = 250,000,000 ns)
        pw-cli set-param "$NODE_ID" ProcessLatency '{ rate = 11025, ns = 250000000 }' >/dev/null 2>&1 || true
        # Ensure bit-perfect audio stream (monitor.channel-volumes = false) & max sinc resample quality
        pw-cli set-param "$NODE_ID" Props '{ params = [ "monitor.channel-volumes" false "resample.quality" 10 ] }' >/dev/null 2>&1 || true
        echo -e "${GREEN}[✓] Hot-applied 250ms ProcessLatency & bit-perfect PCM to Node #${NODE_ID} (zero playback disruption!)${NC}"
    else
        echo -e "${YELLOW}[i] HomePod sink node not currently running in PipeWire graph. Configuration will take effect automatically upon sink creation.${NC}"
    fi
fi

# ------------------------------------------------------------------------------
# Step 4: Install Systemd User Service
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Installing systemd user unit...${NC}"
mkdir -p "$SYSTEMD_USER_DIR"
cp -f "${SCRIPT_DIR}/systemd/sonus.service" "${SYSTEMD_USER_DIR}/sonus.service"
systemctl --user daemon-reload
echo -e "${GREEN}[✓] Installed ${SYSTEMD_USER_DIR}/sonus.service & reloaded daemon${NC}"

# ------------------------------------------------------------------------------
# Step 5: Service Migration & Activation (--enable)
# ------------------------------------------------------------------------------
if [ "$ENABLE_SERVICE" = true ]; then
    echo -e "${CYAN}[*] Migration flag --enable detected. Performing clean handover...${NC}"

    # Stop and disable legacy Python audio driver if running
    if systemctl --user is-active --quiet homelab-homepod-audio.service 2>/dev/null; then
        echo -e "${YELLOW}[!] Stopping legacy Python service (homelab-homepod-audio.service)...${NC}"
        systemctl --user stop homelab-homepod-audio.service || true
    fi
    if systemctl --user is-enabled --quiet homelab-homepod-audio.service 2>/dev/null; then
        echo -e "${YELLOW}[!] Disabling legacy Python service autostart...${NC}"
        systemctl --user disable homelab-homepod-audio.service || true
    fi

    # Enable and start/restart production sonus-rs service
    echo -e "${CYAN}[*] Enabling and starting sonus.service...${NC}"
    systemctl --user enable sonus.service
    systemctl --user restart sonus.service
    echo -e "${GREEN}[✓] sonus.service is active and running!${NC}"
    echo ""
    systemctl --user status sonus.service --no-pager || true
else
    echo ""
    echo -e "${BOLD}Installation completed successfully!${NC}"
    echo -e "To start the background daemon, run:"
    echo -e "  ${CYAN}systemctl --user enable --now sonus.service${NC}"
    echo ""
    echo -e "Or test manually:"
    echo -e "  ${CYAN}sonus probe --host 192.168.1.100${NC}"
    echo -e "  ${CYAN}sonus stream-tone --host 192.168.1.100 --freq 440 --duration 5${NC}"
    echo -e "  ${CYAN}sonus daemon${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}✓ sonus-rs setup complete.${NC}"
