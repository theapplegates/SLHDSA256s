#!/usr/bin/env bash

# SLHDSA256s + MLKEM1024_X448 Post-Quantum Key Generation Automation Script
#
# This script automates the process of building and running the PQC key generation
# example with the correct environment configuration for OpenSSL backend.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect OS and set OpenSSL paths
detect_openssl() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - check for Homebrew OpenSSL
        if [ -d "/opt/homebrew/opt/openssl@3" ]; then
            export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
            export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
            export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
            export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
            export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
            export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
            echo -e "${GREEN}✓${NC} Detected macOS with Homebrew OpenSSL 3"
        elif [ -d "/usr/local/opt/openssl@3" ]; then
            export OPENSSL_DIR=/usr/local/opt/openssl@3
            export OPENSSL_LIB_DIR=/usr/local/opt/openssl@3/lib
            export OPENSSL_INCLUDE_DIR=/usr/local/opt/openssl@3/include
            export PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig
            export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/local/opt/openssl@3/include"
            export RUSTFLAGS="-L/usr/local/opt/openssl@3/lib"
            echo -e "${GREEN}✓${NC} Detected macOS with Homebrew OpenSSL 3 (Intel)"
        else
            echo -e "${YELLOW}⚠${NC} OpenSSL 3 not found in Homebrew. Using system OpenSSL."
        fi
    else
        # Linux - use system OpenSSL
        echo -e "${GREEN}✓${NC} Using system OpenSSL"
    fi
}

# Check OpenSSL version
check_openssl() {
    echo -e "${BLUE}==>${NC} Checking OpenSSL version..."
    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version)
        echo -e "${GREEN}✓${NC} $OPENSSL_VERSION"

        # Extract version number
        if [[ $OPENSSL_VERSION =~ OpenSSL\ ([0-9]+)\.([0-9]+) ]]; then
            MAJOR="${BASH_REMATCH[1]}"
            MINOR="${BASH_REMATCH[2]}"

            if [ "$MAJOR" -lt 3 ]; then
                echo -e "${YELLOW}⚠${NC} Warning: OpenSSL 3.x or higher recommended for full PQC support"
                echo -e "${YELLOW}⚠${NC} Current version: $MAJOR.$MINOR"
            fi
        fi
    else
        echo -e "${RED}✗${NC} OpenSSL not found. Please install OpenSSL 3.x or higher."
        exit 1
    fi
}

# Check Rust version
check_rust() {
    echo -e "${BLUE}==>${NC} Checking Rust version..."
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version)
        echo -e "${GREEN}✓${NC} $RUST_VERSION"
    else
        echo -e "${RED}✗${NC} Rust not found. Please install Rust 1.85 or higher."
        echo "Visit: https://rustup.rs/"
        exit 1
    fi
}

# Build the example
build() {
    echo -e "${BLUE}==>${NC} Building with OpenSSL backend..."
    detect_openssl

    cargo build --release -p sequoia-openpgp \
        --example slhdsa_mlkem_demo \
        --no-default-features \
        --features crypto-openssl,compression

    echo -e "${GREEN}✓${NC} Build completed successfully"
}

# Generate keys
generate() {
    local name="${1:-Example User}"
    local email="${2:-user@example.com}"

    echo -e "${BLUE}==>${NC} Generating post-quantum keys..."
    echo -e "Name: ${name}"
    echo -e "Email: ${email}"
    echo ""

    detect_openssl

    cargo run --release -p sequoia-openpgp \
        --example slhdsa_mlkem_demo \
        --no-default-features \
        --features crypto-openssl,compression \
        -- "$name" "$email"
}

# Show key information
info() {
    echo -e "${BLUE}==>${NC} Key Information"
    echo ""

    # Find generated keys
    PUBLIC_KEYS=($(find . -maxdepth 1 -name "*_public.asc" -type f 2>/dev/null))
    SECRET_KEYS=($(find . -maxdepth 1 -name "*_secret.asc" -type f 2>/dev/null))

    if [ ${#PUBLIC_KEYS[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠${NC} No keys found. Generate keys first with: $0 generate"
        exit 1
    fi

    echo "Found ${#PUBLIC_KEYS[@]} key pair(s):"
    echo ""

    for key in "${PUBLIC_KEYS[@]}"; do
        basename=$(basename "$key" "_public.asc")
        public_key="${basename}_public.asc"
        secret_key="${basename}_secret.asc"

        echo -e "${GREEN}Key pair:${NC} $basename"

        if [ -f "$public_key" ]; then
            size=$(stat -f%z "$public_key" 2>/dev/null || stat -c%s "$public_key" 2>/dev/null)
            echo "  Public: $public_key ($size bytes)"
        fi

        if [ -f "$secret_key" ]; then
            size=$(stat -f%z "$secret_key" 2>/dev/null || stat -c%s "$secret_key" 2>/dev/null)
            echo "  Secret: $secret_key ($size bytes)"
        fi

        echo ""
    done
}

# Run tests
test() {
    echo -e "${BLUE}==>${NC} Running tests with OpenSSL backend..."
    detect_openssl

    cargo test -p sequoia-openpgp \
        --no-default-features \
        --features crypto-openssl,compression

    echo -e "${GREEN}✓${NC} Tests completed"
}

# Clean generated keys
clean() {
    echo -e "${BLUE}==>${NC} Cleaning generated keys..."

    # Find and remove generated keys
    KEYS=($(find . -maxdepth 1 -name "*_public.asc" -o -name "*_secret.asc" 2>/dev/null))

    if [ ${#KEYS[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠${NC} No keys to clean"
        exit 0
    fi

    echo "Found ${#KEYS[@]} key file(s) to remove:"
    for key in "${KEYS[@]}"; do
        echo "  - $key"
    done

    read -p "Remove these files? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "${KEYS[@]}"
        echo -e "${GREEN}✓${NC} Keys removed"
    else
        echo "Cancelled"
    fi
}

# Show help
help() {
    cat << EOF
${GREEN}SLHDSA256s + MLKEM1024_X448 Post-Quantum Key Generation${NC}

${BLUE}Usage:${NC}
  $0 <command> [options]

${BLUE}Commands:${NC}
  ${GREEN}check${NC}       Check system requirements (OpenSSL, Rust)
  ${GREEN}build${NC}       Build the example with OpenSSL backend
  ${GREEN}generate${NC}    Generate post-quantum keys
              Usage: $0 generate [name] [email]
              Example: $0 generate "Alice" "alice@example.com"
  ${GREEN}info${NC}        Display information about generated keys
  ${GREEN}test${NC}        Run tests with OpenSSL backend
  ${GREEN}clean${NC}       Remove generated key files
  ${GREEN}help${NC}        Show this help message

${BLUE}Environment Setup:${NC}
  The script automatically detects and configures OpenSSL paths.

  For macOS:
    brew install openssl@3

  For Linux:
    Use your distribution's package manager to install OpenSSL 3.x

${BLUE}Examples:${NC}
  # Check requirements
  $0 check

  # Generate keys with default values
  $0 generate

  # Generate keys with custom name and email
  $0 generate "Paul Applegate" "me@paulapplegate.com"

  # Show generated key information
  $0 info

  # Clean up
  $0 clean

${BLUE}Key Features:${NC}
  • Primary key: SLHDSA256s (certification + signing)
  • Signing subkey: SLHDSA256s
  • Encryption subkey: MLKEM1024_X448
  • Profile: V6 (RFC 9580)
  • Hash: SHA3-512 (automatic with V6)

${BLUE}Note:${NC}
  Post-quantum keys are large (~200KB) due to algorithm overhead.
  This is expected and normal for PQC algorithms.

EOF
}

# Main command dispatcher
main() {
    case "${1:-help}" in
        check)
            check_rust
            check_openssl
            ;;
        build)
            build
            ;;
        generate)
            shift
            generate "$@"
            ;;
        info)
            info
            ;;
        test)
            test
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            help
            ;;
        *)
            echo -e "${RED}Error:${NC} Unknown command: $1"
            echo "Run '$0 help' for usage information."
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
