#!/data/data/com.termux/files/usr/bin/bash
#
# VeriForge Security Platform - Android/Termux Installer
# =====================================================
# This script installs VeriForge (scanner, dashboard, privacy audit)
# inside a Termux environment on Android devices.
#
# Usage:
#   bash install.sh
#   bash install.sh --no-scan       # skip final verification scan
#   bash install.sh --sdk-only      # install only the SDK
#   bash install.sh --help          # show this help
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
readonly APP_NAME="VeriForge"
readonly APP_VERSION="1.0.0"
readonly REPO_URL="https://github.com/CSP7211/VeriForge.git"
readonly INSTALL_DIR="$HOME/VeriForge"
readonly LOG_FILE="$HOME/veriforge_install.log"
readonly MAX_RETRIES=3
readonly RETRY_DELAY=5

# Feature flags (set by CLI args)
SKIP_VERIFY_SCAN=false
SDK_ONLY=false

# ---------------------------------------------------------------------------
# Color codes for Termux (always use if stdout is a TTY)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; BOLD=''; NC=''
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC}  $*"
    log "[INFO] $*"
}

ok() {
    echo -e "${GREEN}[OK]${NC}    $*"
    log "[OK] $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC}  $*"
    log "[WARN] $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    log "[ERROR] $*"
}

die() {
    error "$*"
    error "Installation failed. Check the log: $LOG_FILE"
    exit 1
}

# ---------------------------------------------------------------------------
# Fancy banners
# ---------------------------------------------------------------------------
banner() {
    echo -e ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${MAGENTA}  V e r i F o r g e${NC}  ${CYAN}-${NC}  ${BOLD}Security Platform${NC}                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}           Android / Termux Installer v${APP_VERSION}             ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
}

section() {
    local title="$1"
    echo -e ""
    echo -e "${BOLD}${CYAN}▶ ${title}${NC}"
    echo -e "${CYAN}$(printf '─%.0s' $(seq 1 $((${#title}+3))))${NC}"
}

progress() {
    local current="$1"
    local total="$2"
    local label="$3"
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))
    local empty=$(( 20 - filled ))
    local bar_filled=$(printf '%*s' "$filled" '' | tr ' ' '█')
    local bar_empty=$(printf '%*s' "$empty" '' | tr ' ' '░')
    printf "\r  ${CYAN}[%s%s]${NC} %3d%%  %s" "$bar_filled" "$bar_empty" "$pct" "$label"
    if [[ "$current" -eq "$total" ]]; then
        echo -e ""
    fi
}

# ---------------------------------------------------------------------------
# Spinner for long-running commands
# ---------------------------------------------------------------------------
spin() {
    local pid=$1
    local msg="$2"
    local delay=0.15
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spin_chars}; i++ )); do
            printf "\r  ${CYAN}%s${NC} %s" "${spin_chars:$i:1}" "$msg"
            sleep "$delay"
            if ! kill -0 "$pid" 2>/dev/null; then
                break 2
            fi
        done
    done
    printf "\r  ${GREEN}✔${NC}  %s\n" "$msg"
    wait "$pid" 2>/dev/null || true
    return ${PIPESTATUS[0]:-0}
}

# ---------------------------------------------------------------------------
# Retry wrapper for network operations
# ---------------------------------------------------------------------------
retry_cmd() {
    local attempt=1
    local exit_code=0
    while [[ $attempt -le $MAX_RETRIES ]]; do
        exit_code=0
        "$@" || exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            return 0
        fi
        warn "Command failed (attempt $attempt/$MAX_RETRIES): $*"
        if [[ $attempt -lt $MAX_RETRIES ]]; then
            info "Retrying in ${RETRY_DELAY} seconds..."
            sleep "$RETRY_DELAY"
        fi
        ((attempt++)) || true
    done
    return "$exit_code"
}

# ---------------------------------------------------------------------------
# Step 1: Environment check
# ---------------------------------------------------------------------------
check_environment() {
    section "Step 1/11 — Environment Check"

    info "Checking Termux environment..."

    if [[ -z "${PREFIX:-}" ]]; then
        die "Not running inside Termux.\n\n" \
            "Please install Termux from F-Droid first:\n" \
            "  https://f-droid.org/packages/com.termux/\n\n" \
            "Then run this script inside Termux."
    fi
    ok "Running inside Termux (PREFIX=$PREFIX)"

    if [[ "$(uname -o)" != "Android" ]]; then
        warn "uname -o reports '$(uname -o)', not 'Android'. Proceeding anyway."
    fi

    local arch
    arch=$(uname -m)
    ok "Architecture: $arch"

    local free_space
    free_space=$(df "$HOME" | awk 'NR==2 {print $4}')
    if [[ "$free_space" -lt 500000 ]]; then  # ~500 MB
        warn "Less than 500 MB free space. Installation may fail."
    else
        ok "Sufficient disk space available"
    fi

    # Check network
    info "Checking network connectivity..."
    if curl -s --max-time 10 -o /dev/null "$REPO_URL"; then
        ok "Network connectivity confirmed"
    else
        warn "Could not reach GitHub. Git clone may fail."
    fi
}

# ---------------------------------------------------------------------------
# Step 2: Update packages
# ---------------------------------------------------------------------------
update_packages() {
    section "Step 2/11 — Updating Termux Packages"

    info "Running pkg update (this may take a few minutes)..."
    retry_cmd pkg update -y &>/dev/null &
    local pid=$!
    spin "$pid" "Updating package lists..."
    wait "$pid" || die "pkg update failed"
    ok "Package lists updated"

    info "Running pkg upgrade..."
    pkg upgrade -y &>/dev/null &
    pid=$!
    spin "$pid" "Upgrading installed packages..."
    wait "$pid" || warn "pkg upgrade had issues, continuing..."
    ok "Packages upgraded"
}

# ---------------------------------------------------------------------------
# Step 3: Install dependencies
# ---------------------------------------------------------------------------
install_deps() {
    section "Step 3/11 — Installing System Dependencies"

    local deps=(python git openssl)
    info "Installing: ${deps[*]}"

    retry_cmd pkg install "${deps[@]}" -y &>/dev/null &
    local pid=$!
    spin "$pid" "Installing python, git, openssl..."
    wait "$pid" || die "Failed to install dependencies"
    ok "System dependencies installed"
}

# ---------------------------------------------------------------------------
# Step 4: Install pip packages
# ---------------------------------------------------------------------------
install_pip_packages() {
    section "Step 4/11 — Installing Python Packages"

    info "Upgrading pip..."
    pip install --upgrade pip &>/dev/null &
    local pid=$!
    spin "$pid" "Upgrading pip..."
    wait "$pid" || warn "pip upgrade had issues, continuing..."

    info "Installing: cryptography jinja2"
    pip install cryptography jinja2 &>/dev/null &
    pid=$!
    spin "$pid" "Installing cryptography, jinja2..."
    wait "$pid" || die "Failed to install pip packages"
    ok "Python packages installed"
}

# ---------------------------------------------------------------------------
# Step 5: Download VeriForge
# ---------------------------------------------------------------------------
download_veriforge() {
    section "Step 5/11 — Downloading VeriForge"

    if [[ -d "$INSTALL_DIR" ]]; then
        warn "Directory $INSTALL_DIR already exists."
        read -rp "  Pull latest changes instead? [Y/n]: " ans
        if [[ "${ans:-Y}" =~ ^[Yy] ]]; then
            info "Pulling latest changes..."
            (cd "$INSTALL_DIR" && git pull) &>/dev/null &
            local pid=$!
            spin "$pid" "Updating VeriForge repository..."
            wait "$pid" || warn "git pull failed, using existing code"
        fi
    else
        info "Cloning from $REPO_URL ..."
        retry_cmd git clone "$REPO_URL" "$INSTALL_DIR" &>/dev/null &
        local pid=$!
        spin "$pid" "Cloning VeriForge repository..."
        wait "$pid" || die "Failed to clone VeriForge repository"
    fi
    ok "VeriForge source ready at $INSTALL_DIR"
}

# ---------------------------------------------------------------------------
# Step 6: Install SDK
# ---------------------------------------------------------------------------
install_sdk() {
    section "Step 6/11 — Installing VeriForge SDK"

    local sdk_dir="$INSTALL_DIR/veriforge-sdk"
    if [[ ! -d "$sdk_dir" ]]; then
        warn "SDK directory not found at $sdk_dir"
        info "Attempting alternative paths..."
        if [[ -d "$INSTALL_DIR/veriforge_sdk" ]]; then
            sdk_dir="$INSTALL_DIR/veriforge_sdk"
        elif [[ -d "$INSTALL_DIR/sdk" ]]; then
            sdk_dir="$INSTALL_DIR/sdk"
        else
            die "Could not find SDK directory."
        fi
    fi

    info "Installing SDK from $sdk_dir ..."
    (cd "$sdk_dir" && pip install -e .) &>/dev/null &
    local pid=$!
    spin "$pid" "Installing veriforge-sdk (editable)..."
    wait "$pid" || die "SDK installation failed"
    ok "VeriForge SDK installed"
}

# ---------------------------------------------------------------------------
# Step 7: Install VeriForge Red
# ---------------------------------------------------------------------------
install_red() {
    if [[ "$SDK_ONLY" == true ]]; then
        info "SDK-only mode — skipping VeriForge Red installation"
        return 0
    fi

    section "Step 7/11 — Installing VeriForge Red (Scanner)"

    local red_dir="$INSTALL_DIR/veriforge_red"
    if [[ ! -d "$red_dir" ]]; then
        warn "Red directory not found at $red_dir"
        info "Attempting alternative paths..."
        if [[ -d "$INSTALL_DIR/veriforge-red" ]]; then
            red_dir="$INSTALL_DIR/veriforge-red"
        elif [[ -d "$INSTALL_DIR/red" ]]; then
            red_dir="$INSTALL_DIR/red"
        else
            die "Could not find VeriForge Red directory."
        fi
    fi

    info "Installing VeriForge Red from $red_dir ..."
    (cd "$red_dir" && pip install -e .) &>/dev/null &
    local pid=$!
    spin "$pid" "Installing veriforge-red (editable)..."
    wait "$pid" || die "VeriForge Red installation failed"
    ok "VeriForge Red installed"
}

# ---------------------------------------------------------------------------
# Step 8: Create launcher scripts
# ---------------------------------------------------------------------------
create_launchers() {
    section "Step 8/11 — Creating Launcher Scripts"

    local bin_dir="$PREFIX/bin"
    mkdir -p "$bin_dir"

    # --- veriforge-red (scanner) ---
    cat > "$bin_dir/veriforge-red" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Red — Security Scanner Launcher
# Usage: veriforge-red [target_path] [options]

set -e

TARGET="${1:-/sdcard}"
shift 1 || true

echo "[VeriForge Red] Starting scan..."
echo "  Target: $TARGET"
echo ""

if command -v veriforge-red &>/dev/null; then
    veriforge-red scan "$TARGET" "$@"
else
    # Fallback: try python module
    python -m veriforge_red scan "$TARGET" "$@" || \
    python "$HOME/VeriForge/veriforge_red/veriforge_red/main.py" scan "$TARGET" "$@" || \
    echo "[ERROR] Could not launch scanner. Check installation."
fi
EOF
    chmod +x "$bin_dir/veriforge-red"
    ok "Created: veriforge-red"

    # --- veriforge-dashboard ---
    cat > "$bin_dir/veriforge-dashboard" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Dashboard — HTTP Dashboard Launcher
# Usage: veriforge-dashboard [port]

set -e

PORT="${1:-8080}"

echo "[VeriForge Dashboard] Starting HTTP server on port $PORT..."
echo "  Open http://localhost:$PORT in your browser"
echo "  Press Ctrl+C to stop"
echo ""

if command -v veriforge-red &>/dev/null; then
    veriforge-red dashboard --port "$PORT"
else
    python -m veriforge_red dashboard --port "$PORT" 2>/dev/null || \
    python "$HOME/VeriForge/veriforge_red/veriforge_red/main.py" dashboard --port "$PORT" 2>/dev/null || \
    echo "[ERROR] Could not launch dashboard. Check installation."
fi
EOF
    chmod +x "$bin_dir/veriforge-dashboard"
    ok "Created: veriforge-dashboard"

    # --- veriforge-privacy ---
    cat > "$bin_dir/veriforge-privacy" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Privacy — Privacy Audit Launcher
# Usage: veriforge-privacy [target_path]

set -e

TARGET="${1:-/sdcard}"

echo "[VeriForge Privacy] Starting privacy audit..."
echo "  Target: $TARGET"
echo ""

if command -v veriforge-red &>/dev/null; then
    veriforge-red privacy "$TARGET"
else
    python -m veriforge_red privacy "$TARGET" 2>/dev/null || \
    python "$HOME/VeriForge/veriforge_red/veriforge_red/main.py" privacy "$TARGET" 2>/dev/null || \
    echo "[ERROR] Could not launch privacy audit. Check installation."
fi
EOF
    chmod +x "$bin_dir/veriforge-privacy"
    ok "Created: veriforge-privacy"

    # --- veriforge-sdk ---
    cat > "$bin_dir/veriforge-sdk" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge SDK — SDK CLI Launcher
# Usage: veriforge-sdk [command] [options]

set -e

if command -v veriforge-sdk &>/dev/null; then
    veriforge-sdk "$@"
else
    python -m veriforge_sdk "$@" 2>/dev/null || \
    python "$HOME/VeriForge/veriforge-sdk/veriforge_sdk/cli.py" "$@" 2>/dev/null || \
    echo "[ERROR] Could not launch SDK CLI. Check installation."
fi
EOF
    chmod +x "$bin_dir/veriforge-sdk"
    ok "Created: veriforge-sdk"
}

# ---------------------------------------------------------------------------
# Step 9: Create Android home screen shortcut
# ---------------------------------------------------------------------------
create_shortcut() {
    section "Step 9/11 — Creating Android Shortcut"

    local shortcut_dir="$HOME/.shortcuts"
    local tasks_dir="$HOME/.termux/tasker"

    # Termux:Widget support
    if [[ -d "$shortcut_dir" ]] || mkdir -p "$shortcut_dir" 2>/dev/null; then
        cat > "$shortcut_dir/VeriForge-Scan" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Quick Scan — Android Widget Shortcut
echo "=== VeriForge Quick Scan ==="
veriforge-red /sdcard --quick
read -n 1 -s -r -p "Press any key to exit..."
EOF
        chmod +x "$shortcut_dir/VeriForge-Scan"
        ok "Created Termux:Widget shortcut: VeriForge-Scan"
    fi

    # Termux:Tasker support
    if [[ -d "$tasks_dir" ]] || mkdir -p "$tasks_dir" 2>/dev/null; then
        cat > "$tasks_dir/veriforge-scan.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Scan — Tasker integration
veriforge-red "${1:-/sdcard}" --quick
EOF
        chmod +x "$tasks_dir/veriforge-scan.sh"
        ok "Created Termux:Tasker script: veriforge-scan.sh"
    fi

    info "To add a home screen widget:"
    info "  1. Install 'Termux:Widget' from F-Droid"
    info "  2. Long-press home screen → Widgets"
    info "  3. Find 'Termux' → drag shortcut to home screen"
}

# ---------------------------------------------------------------------------
# Step 10: Verify installation
# ---------------------------------------------------------------------------
verify_installation() {
    section "Step 10/11 — Verifying Installation"

    local total_checks=5
    local passed=0

    progress 1 "$total_checks" "Checking Python..."
    if command -v python &>/dev/null; then
        ok "Python: $(python --version)"
        ((passed++)) || true
    else
        error "Python not found"
    fi

    progress 2 "$total_checks" "Checking pip packages..."
    if python -c "import cryptography, jinja2" 2>/dev/null; then
        ok "cryptography and jinja2 are importable"
        ((passed++)) || true
    else
        error "Python packages not found"
    fi

    progress 3 "$total_checks" "Checking launchers..."
    local all_ok=true
    for script in veriforge-red veriforge-dashboard veriforge-privacy veriforge-sdk; do
        if [[ -x "$PREFIX/bin/$script" ]]; then
            log "Launcher OK: $script"
        else
            error "Launcher missing: $script"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == true ]]; then
        ok "All launcher scripts present"
        ((passed++)) || true
    fi

    progress 4 "$total_checks" "Checking source code..."
    if [[ -d "$INSTALL_DIR" ]]; then
        ok "Source code at $INSTALL_DIR"
        ((passed++)) || true
    else
        error "Source code directory missing"
    fi

    progress 5 "$total_checks" "Checking SDK install..."
    if python -c "import veriforge_sdk" 2>/dev/null || \
       python -c "import veriforge_sdk" 2>/dev/null; then
        ok "SDK module importable"
        ((passed++)) || true
    else
        warn "SDK module not directly importable (may be package name difference)"
    fi

    echo -e ""
    if [[ "$passed" -eq "$total_checks" ]]; then
        echo -e "${GREEN}${BOLD}  ✔  All ${passed}/${total_checks} checks passed${NC}"
    else
        echo -e "${YELLOW}${BOLD}  ⚠  ${passed}/${total_checks} checks passed${NC}"
    fi

    # Quick scan verification (optional)
    if [[ "$SKIP_VERIFY_SCAN" == false && "$SDK_ONLY" == false ]]; then
        info "Running quick verification scan..."
        info "  (Use --no-scan to skip this step)"
        echo -e ""

        local test_dir="$HOME/veriforge_test"
        mkdir -p "$test_dir"
        echo "test file" > "$test_dir/test.txt"

        if veriforge-red "$test_dir" --quick 2>&1 | head -n 20; then
            ok "Verification scan completed"
        else
            warn "Verification scan had issues (non-critical)"
        fi

        rm -rf "$test_dir"
    fi
}

# ---------------------------------------------------------------------------
# Step 11: Completion message
# ---------------------------------------------------------------------------
show_completion() {
    section "Step 11/11 — Installation Complete!"

    echo -e ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║               INSTALLATION SUCCESSFUL!                       ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${BOLD}Installed:${NC}"
    echo -e "  ${CYAN}•${NC} VeriForge SDK      — Core security library"
    echo -e "  ${CYAN}•${NC} VeriForge Red      — Security scanner engine"
    echo -e "  ${CYAN}•${NC} Python packages    — cryptography, jinja2"
    echo -e ""
    echo -e "${BOLD}Available Commands:${NC}"
    echo -e "  ${GREEN}veriforge-red${NC}         Quick security scan"
    echo -e "  ${GREEN}veriforge-red /sdcard${NC} Scan specific path"
    echo -e "  ${GREEN}veriforge-dashboard${NC}   Start HTTP dashboard (port 8080)"
    echo -e "  ${GREEN}veriforge-privacy${NC}     Run privacy audit"
    echo -e "  ${GREEN}veriforge-sdk${NC}         SDK CLI tools"
    echo -e ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${YELLOW}$${NC} veriforge-red /sdcard/Download"
    echo -e "  ${YELLOW}$${NC} veriforge-dashboard 8888"
    echo -e "  ${YELLOW}$${NC} veriforge-privacy /sdcard"
    echo -e ""
    echo -e "${BOLD}Android Shortcuts:${NC}"
    echo -e "  Install 'Termux:Widget' from F-Droid and add shortcuts"
    echo -e "  to your home screen for one-tap scanning."
    echo -e ""
    echo -e "${BOLD}Next Steps:${NC}"
    echo -e "  1. Grant storage permission: ${YELLOW}termux-setup-storage${NC}"
    echo -e "  2. Run a quick scan:        ${YELLOW}veriforge-red${NC}"
    echo -e "  3. Open dashboard:          ${YELLOW}veriforge-dashboard${NC}"
    echo -e ""
    echo -e "${BOLD}Support:${NC}"
    echo -e "  Log file: $LOG_FILE"
    echo -e "  GitHub:   $REPO_URL"
    echo -e ""
}

# ---------------------------------------------------------------------------
# Signal handler for Ctrl+C
# ---------------------------------------------------------------------------
trap_ctrlc() {
    echo -e ""
    error "Interrupted by user (Ctrl+C)"
    info "Partial log saved to: $LOG_FILE"
    exit 130
}
trap trap_ctrlc INT

# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-scan)
                SKIP_VERIFY_SCAN=true
                shift
                ;;
            --sdk-only)
                SDK_ONLY=true
                shift
                ;;
            --help|-h)
                echo "VeriForge Android Installer v$APP_VERSION"
                echo ""
                echo "Usage: bash install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --no-scan      Skip the final verification scan"
                echo "  --sdk-only     Install only the SDK (no scanner)"
                echo "  --help, -h     Show this help message"
                echo ""
                echo "Example:"
                echo "  bash install.sh"
                echo "  bash install.sh --no-scan"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                info "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Main installer flow
# ---------------------------------------------------------------------------
main() {
    # Clear / create log file
    : > "$LOG_FILE"
    log "=== VeriForge Installer v$APP_VERSION started ==="

    parse_args "$@"
    banner

    local total_steps=11
    local step=0

    progress "$((++step))" "$total_steps" "Environment check"
    check_environment

    progress "$((++step))" "$total_steps" "Updating packages"
    update_packages

    progress "$((++step))" "$total_steps" "Installing dependencies"
    install_deps

    progress "$((++step))" "$total_steps" "Installing pip packages"
    install_pip_packages

    progress "$((++step))" "$total_steps" "Downloading VeriForge"
    download_veriforge

    progress "$((++step))" "$total_steps" "Installing SDK"
    install_sdk

    progress "$((++step))" "$total_steps" "Installing VeriForge Red"
    install_red

    progress "$((++step))" "$total_steps" "Creating launchers"
    create_launchers

    progress "$((++step))" "$total_steps" "Creating shortcuts"
    create_shortcut

    progress "$((++step))" "$total_steps" "Verifying installation"
    verify_installation

    progress "$((++step))" "$total_steps" "Done!"
    show_completion

    log "=== Installation completed successfully ==="
}

main "$@"
