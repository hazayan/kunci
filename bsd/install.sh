#!/bin/sh

# Kunci installation script for FreeBSD
# This script builds and installs Kunci on FreeBSD systems.

set -e

# Default values
INSTALL_PREFIX="/usr/local"
CARGO_BUILD_FLAGS="--release"
BINARY_NAME="kunci"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    info "Checking system requirements..."
    
    # Check for Rust
    if ! command -v rustc >/dev/null 2>&1; then
        warn "Rust not found. Attempting to install via pkg..."
        pkg install -y rust
    fi
    
    # Check for Cargo
    if ! command -v cargo >/dev/null 2>&1; then
        error "Cargo not found even after Rust installation attempt."
        exit 1
    fi
    
    # Check for git (optional, for building from git)
    if ! command -v git >/dev/null 2>&1; then
        warn "Git not found. Installing..."
        pkg install -y git
    fi
    
    info "Requirements satisfied."
}

build_kunci() {
    info "Building Kunci..."
    
    # Check if we're in the kunci directory
    if [ -f "Cargo.toml" ] && [ -d "core" ] && [ -d "client" ]; then
        info "Building from current directory..."
    else
        # Try to find the project root
        if [ -f "../Cargo.toml" ]; then
            info "Building from parent directory..."
            cd ..
        else
            error "Not in Kunci project directory. Please run from the kunci root directory."
            exit 1
        fi
    fi
    
    # Build the project
    cargo build ${CARGO_BUILD_FLAGS}
    
    if [ $? -ne 0 ]; then
        error "Build failed."
        exit 1
    fi
    
    info "Build successful."
}

install_binary() {
    info "Installing binary to ${INSTALL_PREFIX}/bin..."
    
    mkdir -p "${INSTALL_PREFIX}/bin"
    cp "target/release/${BINARY_NAME}" "${INSTALL_PREFIX}/bin/"
    chmod 755 "${INSTALL_PREFIX}/bin/${BINARY_NAME}"
    
    info "Binary installed."
}

install_rc_script() {
    info "Installing rc.d script..."
    
    if [ -f "bsd/kunci_zfs" ]; then
        mkdir -p "${INSTALL_PREFIX}/etc/rc.d"
        cp "bsd/kunci_zfs" "${INSTALL_PREFIX}/etc/rc.d/"
        chmod 555 "${INSTALL_PREFIX}/etc/rc.d/kunci_zfs"
        info "rc.d script installed to ${INSTALL_PREFIX}/etc/rc.d/kunci_zfs"
    else
        warn "rc.d script not found at bsd/kunci_zfs. Skipping."
    fi
}

install_man_pages() {
    # Check if man pages exist
    if [ -d "docs/man" ]; then
        info "Installing man pages..."
        
        for man_section in 1 5 8; do
            if [ -d "docs/man/man${man_section}" ]; then
                mkdir -p "${INSTALL_PREFIX}/man/man${man_section}"
                cp docs/man/man${man_section}/* "${INSTALL_PREFIX}/man/man${man_section}/" 2>/dev/null || true
            fi
        done
        
        info "Man pages installed."
    else
        info "No man pages found. Skipping."
    fi
}

create_config_dir() {
    info "Creating configuration directory..."
    
    mkdir -p "${INSTALL_PREFIX}/etc/kunci"
    if [ -f "bsd/kunci.conf.example" ]; then
        cp bsd/kunci.conf.example "${INSTALL_PREFIX}/etc/kunci/kunci.conf.example"
        info "Example configuration installed to ${INSTALL_PREFIX}/etc/kunci/kunci.conf.example"
    fi
    
    # Also create user config directory
    mkdir -p "/usr/home/$(whoami)/.config/kunci" 2>/dev/null || true
}

show_post_install() {
    echo ""
    info "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "1. Add ${INSTALL_PREFIX}/bin to your PATH if it's not already there"
    echo "2. Configure Kunci for ZFS by editing ${INSTALL_PREFIX}/etc/kunci/kunci.conf.example"
    echo "3. Copy the rc.d script to /usr/local/etc/rc.d/ and enable it in /etc/rc.conf"
    echo ""
    echo "For more information, see bsd/README.md"
    echo ""
}

main() {
    info "Starting Kunci installation for FreeBSD"
    
    check_requirements
    build_kunci
    install_binary
    install_rc_script
    install_man_pages
    create_config_dir
    show_post_install
    
    info "Done."
}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case $1 in
        --prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        --debug)
            CARGO_BUILD_FLAGS=""
            shift
            ;;
        *)
            error "Unknown option: $1"
            echo "Usage: $0 [--prefix /usr/local] [--debug]"
            exit 1
            ;;
    esac
done

main
