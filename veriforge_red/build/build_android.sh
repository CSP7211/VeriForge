#!/bin/bash
# Build VeriForge Red Android APK
# Usage: ./build_android.sh [debug|release]
#
# Prerequisites:
#   - Python 3.8+
#   - pip
#   - git
#   - java (JDK 11 or 17)
#   - Android SDK/NDK (auto-downloaded by buildozer if missing)
#
# Environment Variables:
#   VERIFORGE_KEYSTORE      Path to release keystore
#   VERIFORGE_KEYPASS       Keystore password
#   VERIFORGE_KEYALIAS      Key alias
#   VERIFORGE_KEYALIASPASS  Key alias password

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_TYPE="${1:-debug}"
VENV_DIR="${PROJECT_ROOT}/.buildozer_venv"
BUILD_LOG="${PROJECT_ROOT}/build.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

preflight() {
    log_info "Running preflight checks..."
    check_command python3
    check_command pip
    check_command git
    check_command java
    log_ok "All required tools are available"

    # Python version check
    PYTHON_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_info "Python version: ${PYTHON_VER}"

    # Java version check
    JAVA_VER=$(java -version 2>&1 | head -n1 | grep -oP '\"[0-9]+(\\.[0-9]+)*\"' | tr -d '"')
    log_info "Java version: ${JAVA_VER}"
}

# ---------------------------------------------------------------------------
# Virtual environment setup
# ---------------------------------------------------------------------------

setup_venv() {
    log_info "Setting up virtual environment..."
    if [[ ! -d "${VENV_DIR}" ]]; then
        python3 -m venv "${VENV_DIR}"
        log_ok "Created virtual environment"
    fi
    source "${VENV_DIR}/bin/activate"
    log_ok "Activated virtual environment"
}

# ---------------------------------------------------------------------------
# Install buildozer and dependencies
# ---------------------------------------------------------------------------

install_buildozer() {
    log_info "Installing buildozer and Cython..."
    pip install --quiet --upgrade pip
    pip install --quiet "cython>=0.29.33"
    pip install --quiet "buildozer>=1.5.0"
    log_ok "buildozer installed: $(buildozer --version 2>/dev/null || echo 'version unknown')"
}

# ---------------------------------------------------------------------------
# Configure signing for release builds
# ---------------------------------------------------------------------------

configure_release() {
    if [[ "${BUILD_TYPE}" != "release" ]]; then
        return 0
    fi

    log_info "Configuring release build signing..."
    if [[ -z "${VERIFORGE_KEYSTORE:-}" ]]; then
        log_warn "VERIFORGE_KEYSTORE not set — release APK will be unsigned"
        log_warn "Set the following environment variables for signed release:"
        log_warn "  export VERIFORGE_KEYSTORE=/path/to/keystore.jks"
        log_warn "  export VERIFORGE_KEYPASS=keystore_password"
        log_warn "  export VERIFORGE_KEYALIAS=alias_name"
        log_warn "  export VERIFORGE_KEYALIASPASS=alias_password"
    else
        log_ok "Using keystore: ${VERIFORGE_KEYSTORE}"
    fi
}

# ---------------------------------------------------------------------------
# Run build
# ---------------------------------------------------------------------------

run_build() {
    log_info "Starting ${BUILD_TYPE} build..."
    cd "${PROJECT_ROOT}"

    # Ensure buildozer.spec is in the right place
    if [[ ! -f "veriforge_red/build/buildozer.spec" ]]; then
        log_error "buildozer.spec not found at veriforge_red/build/buildozer.spec"
        exit 1
    fi

    # Clean previous build artifacts if requested
    if [[ "${CLEAN_BUILD:-0}" == "1" ]]; then
        log_warn "CLEAN_BUILD=1 — removing .buildozer directory"
        rm -rf "${PROJECT_ROOT}/.buildozer"
    fi

    # Build
    if [[ "${BUILD_TYPE}" == "release" && -n "${VERIFORGE_KEYSTORE:-}" ]]; then
        log_info "Building signed release APK..."
        buildozer -v android release \
            --sign --keystore "${VERIFORGE_KEYSTORE}" \
            --keystore_password "${VERIFORGE_KEYPASS}" \
            --keyalias "${VERIFORGE_KEYALIAS}" \
            --keyalias_password "${VERIFORGE_KEYALIASPASS}" \
            2>&1 | tee "${BUILD_LOG}"
    else
        log_info "Building debug APK..."
        buildozer -v android debug 2>&1 | tee "${BUILD_LOG}"
    fi

    log_ok "Build complete!"

    # Show output
    APK_DIR="${PROJECT_ROOT}/bin"
    if [[ -d "${APK_DIR}" ]]; then
        log_info "Output APK(s):"
        ls -lh "${APK_DIR}"/*.apk 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Deploy (optional)
# ---------------------------------------------------------------------------

deploy_apk() {
    if [[ "${DEPLOY:-0}" != "1" ]]; then
        return 0
    fi
    log_info "Deploying to connected device..."
    cd "${PROJECT_ROOT}"
    buildozer android deploy run logcat 2>&1 | tee -a "${BUILD_LOG}" || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    log_info "==================================================="
    log_info "  VeriForge Red — Android Build Script"
    log_info "  Build type: ${BUILD_TYPE}"
    log_info "  Project: ${PROJECT_ROOT}"
    log_info "==================================================="

    preflight
    setup_venv
    install_buildozer
    configure_release
    run_build

    if [[ "${DEPLOY:-0}" == "1" ]]; then
        deploy_apk
    fi

    log_info "All done! Check ${BUILD_LOG} for full details."
}

main "$@"
