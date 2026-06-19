#!/bin/bash
#
# Barzakh Build Automation Script
#
# This script automates the compilation of all EDK II packages for the
# Barzakh project, including SBOM generation, artifact signing, and
# build verification.
#
# USAGE:
#   ./build.sh [OPTIONS]
#
# OPTIONS:
#   --clean              Clean build artifacts before building
#   --release            Build in RELEASE mode (default: DEBUG)
#   --dry-run            Show what would be built without building
#   --skip-signing       Skip artifact signing (for development only)
#   --generate-sbom      Generate Software Bill of Materials
#   --help               Show this help message
#
# REQUIREMENTS:
#   - EDK II environment configured
#   - AEGIS_EXPIRY_DATE set in environment
#   - Artifact signing keys available (unless --skip-signing)

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source environment if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

# Default configuration
WORKSPACE="${WORKSPACE:-$HOME/barzakh-workspace/edk2}"
PACKAGES_PATH="${PACKAGES_PATH:-$WORKSPACE:$PROJECT_ROOT/src}"
TARGET="${TARGET:-DEBUG}"
TOOL_CHAIN_TAG="${TOOL_CHAIN_TAG:-GCC5}"
TARGET_ARCH="${TARGET_ARCH:-X64}"

# Build options
CLEAN_BUILD=false
DRY_RUN=false
SKIP_SIGNING=false
GENERATE_SBOM=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Show usage
show_usage() {
    head -n 25 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)
                CLEAN_BUILD=true
                shift
                ;;
            --release)
                TARGET="RELEASE"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-signing)
                SKIP_SIGNING=true
                log_warning "Artifact signing will be skipped"
                shift
                ;;
            --generate-sbom)
                GENERATE_SBOM=true
                shift
                ;;
            --help)
                show_usage
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                ;;
        esac
    done
}

# Validate environment
validate_environment() {
    log_info "Validating build environment..."

    # Check workspace
    if [[ ! -d "$WORKSPACE" ]]; then
        log_error "EDK II workspace not found: $WORKSPACE"
        log_error "Clone and build EDK II first. See docs/SETUP.md"
        exit 1
    fi

    # Check BaseTools
    if [[ ! -f "$WORKSPACE/BaseTools/Source/C/bin/GenFw" ]]; then
        log_error "EDK II BaseTools not built"
        log_error "Run: cd $WORKSPACE && make -C BaseTools"
        exit 1
    fi

    # Check compiler
    if ! command -v gcc &> /dev/null; then
        log_error "GCC compiler not found"
        exit 1
    fi

    # Check NASM
    if ! command -v nasm &> /dev/null; then
        log_error "NASM assembler not found"
        exit 1
    fi

    # Check signing keys (unless skipped)
    if [[ "$SKIP_SIGNING" == "false" ]]; then
        local signing_key="${ARTIFACT_SIGNING_KEY:-$HOME/barzakh-workspace/keys/artifact-signing-key}"
        if [[ ! -f "$signing_key" ]]; then
            log_warning "Artifact signing key not found: $signing_key"
            log_warning "Generate with: ssh-keygen -t ed25519 -f $signing_key"
            log_warning "Continuing without signing (use --skip-signing to suppress this warning)"
            SKIP_SIGNING=true
        fi
    fi

    log_success "Environment validation passed"
}

# Setup EDK II environment
setup_edk_environment() {
    log_info "Setting up EDK II environment..."

    cd "$WORKSPACE"

    # Source EDK II setup script
    if [[ ! -f "edksetup.sh" ]]; then
        log_error "edksetup.sh not found in $WORKSPACE"
        exit 1
    fi

    # Export environment variables
    export WORKSPACE="$WORKSPACE"
    export PACKAGES_PATH="$PACKAGES_PATH"
    export EDK_TOOLS_PATH="$WORKSPACE/BaseTools"
    export TARGET="$TARGET"
    export TARGET_ARCH="$TARGET_ARCH"
    export TOOL_CHAIN_TAG="$TOOL_CHAIN_TAG"

    # Source setup script (suppress output)
    source edksetup.sh > /dev/null 2>&1

    log_success "EDK II environment configured"
    log_info "  WORKSPACE: $WORKSPACE"
    log_info "  PACKAGES_PATH: $PACKAGES_PATH"
    log_info "  TARGET: $TARGET"
    log_info "  TOOL_CHAIN_TAG: $TOOL_CHAIN_TAG"
}

# Clean build artifacts
clean_build() {
    log_info "Cleaning build artifacts..."

    local build_dir="$WORKSPACE/Build"
    
    if [[ -d "$build_dir" ]]; then
        rm -rf "$build_dir"
        log_success "Build directory cleaned"
    else
        log_info "No build artifacts to clean"
    fi
}

# Build a package
build_package() {
    local pkg_name="$1"
    local pkg_dsc="$2"

    log_info "Building package: $pkg_name"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would build: $pkg_dsc"
        return 0
    fi

    # Build command
    local build_cmd=(
        build
        -a "$TARGET_ARCH"
        -t "$TOOL_CHAIN_TAG"
        -b "$TARGET"
        -p "$pkg_dsc"
    )

    # Add reproducible build flags
    build_cmd+=(
        -D SOURCE_DATE_EPOCH="$(date -d "${AEGIS_EXPIRY_DATE:-2027-05-11}" +%s)"
    )

    # Execute build
    log_info "Executing: ${build_cmd[*]}"
    
    if "${build_cmd[@]}"; then
        log_success "Package built successfully: $pkg_name"
        return 0
    else
        log_error "Failed to build package: $pkg_name"
        return 1
    fi
}

# Generate SBOM (Software Bill of Materials)
generate_sbom() {
    log_info "Generating Software Bill of Materials (SBOM)..."

    local sbom_file="$PROJECT_ROOT/docs/SBOM-$(date +%Y%m%d-%H%M%S).txt"

    cat > "$sbom_file" <<EOF
# Barzakh Software Bill of Materials (SBOM)
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

## Build Configuration
Build Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Expiry Date: ${AEGIS_EXPIRY_DATE:-Not Set}
Target: ${TARGET}
Architecture: ${TARGET_ARCH}
Toolchain: ${TOOL_CHAIN_TAG}

## EDK II Information
Workspace: ${WORKSPACE}
EDK II Commit: $(cd "$WORKSPACE" && git rev-parse HEAD 2>/dev/null || echo "Unknown")
EDK II Branch: $(cd "$WORKSPACE" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "Unknown")

## Compiler Information
GCC Version: $(gcc --version | head -n1)
NASM Version: $(nasm --version | head -n1)

## Build Artifacts
EOF

    # List all built .efi files
    local build_dir="$WORKSPACE/Build"
    if [[ -d "$build_dir" ]]; then
        log_info "Cataloging build artifacts..."
        find "$build_dir" -name "*.efi" -type f | while read -r efi_file; do
            local hash=$(sha256sum "$efi_file" | cut -d' ' -f1)
            local size=$(stat -f%z "$efi_file" 2>/dev/null || stat -c%s "$efi_file")
            echo "  - $(basename "$efi_file")" >> "$sbom_file"
            echo "    Path: $efi_file" >> "$sbom_file"
            echo "    SHA256: $hash" >> "$sbom_file"
            echo "    Size: $size bytes" >> "$sbom_file"
            echo "" >> "$sbom_file"
        done
    fi

    # Add dependency information
    cat >> "$sbom_file" <<EOF

## Dependencies
- EDK II: https://github.com/tianocore/edk2
- OVMF: Part of EDK II
- TPM 2.0 Support: Enabled

## Security Bindings
Allowed UUID: ${AEGIS_ALLOWED_UUID:-Not Set}
Expiry Date: ${AEGIS_EXPIRY_DATE:-Not Set}

## Audit Trail
This SBOM is part of the immutable audit trail for project compliance.
All artifacts listed above are subject to the project's security constraints.

EOF

    log_success "SBOM generated: $sbom_file"
}

# Sign artifacts
sign_artifacts() {
    if [[ "$SKIP_SIGNING" == "true" ]]; then
        log_warning "Artifact signing skipped"
        return 0
    fi

    log_info "Signing build artifacts..."

    local signing_key="${ARTIFACT_SIGNING_KEY:-$HOME/barzakh-workspace/keys/artifact-signing-key}"
    local build_dir="$WORKSPACE/Build"

    if [[ ! -d "$build_dir" ]]; then
        log_warning "No build directory found, skipping signing"
        return 0
    fi

    # Find all .efi files and sign them
    local signed_count=0
    find "$build_dir" -name "*.efi" -type f | while read -r efi_file; do
        local sig_file="${efi_file}.sig"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would sign: $efi_file"
        else
            # Create signature using ssh-keygen
            ssh-keygen -Y sign -f "$signing_key" -n barzakh "$efi_file" > "$sig_file" 2>/dev/null
            
            if [[ -f "$sig_file" ]]; then
                log_success "Signed: $(basename "$efi_file")"
                ((signed_count++))
            else
                log_error "Failed to sign: $(basename "$efi_file")"
            fi
        fi
    done

    if [[ $signed_count -gt 0 ]]; then
        log_success "Signed $signed_count artifacts"
    fi
}

# Verify build artifacts
verify_artifacts() {
    log_info "Verifying build artifacts..."

    local build_dir="$WORKSPACE/Build"
    
    if [[ ! -d "$build_dir" ]]; then
        log_warning "No build directory found"
        return 0
    fi

    # Check for expected artifacts
    local expected_artifacts=(
        # Add expected .efi files here as packages are implemented
        # "BootkitPkg/DxeInject/DxeInject.efi"
        # "BootkitPkg/ExitBootHook/ExitBootHook.efi"
        # "AttestationPkg/AttestationDxe.efi"
    )

    local found_count=0
    local total_count=${#expected_artifacts[@]}

    if [[ $total_count -eq 0 ]]; then
        log_info "No expected artifacts defined yet (packages not implemented)"
        return 0
    fi

    for artifact in "${expected_artifacts[@]}"; do
        if find "$build_dir" -path "*/$artifact" -type f | grep -q .; then
            log_success "Found: $artifact"
            ((found_count++))
        else
            log_warning "Missing: $artifact"
        fi
    done

    log_info "Verification: $found_count/$total_count artifacts found"
}

# Main build function
main() {
    parse_args "$@"

    log_info "=== Barzakh Build System ==="
    log_info "Target: $TARGET"
    log_info "Architecture: $TARGET_ARCH"
    log_info "Toolchain: $TOOL_CHAIN_TAG"
    echo

    # Validate environment
    validate_environment

    # Setup EDK II environment
    setup_edk_environment

    # Clean if requested
    if [[ "$CLEAN_BUILD" == "true" ]]; then
        clean_build
    fi

    # Build packages
    log_info "Starting package builds..."
    echo

    # Note: These packages will be built once they are implemented
    # For now, we'll just show what would be built
    
    local packages=(
        # "BootkitPkg:$PROJECT_ROOT/src/BootkitPkg/BootkitPkg.dsc"
        # "AttestationPkg:$PROJECT_ROOT/src/AttestationPkg/AttestationPkg.dsc"
    )

    if [[ ${#packages[@]} -eq 0 ]]; then
        log_warning "No packages defined yet"
        log_info "Packages will be added as they are implemented"
        log_info "Expected packages:"
        log_info "  - BootkitPkg (DXE injection and hooking)"
        log_info "  - AttestationPkg (TPM querying and telemetry)"
        log_info "  - BarzakhScanner (Detection engine)"
    else
        for pkg_entry in "${packages[@]}"; do
            IFS=':' read -r pkg_name pkg_dsc <<< "$pkg_entry"
            build_package "$pkg_name" "$pkg_dsc" || {
                log_error "Build failed for $pkg_name"
                exit 1
            }
        done
    fi

    # Generate SBOM
    if [[ "$GENERATE_SBOM" == "true" ]]; then
        generate_sbom
    fi

    # Sign artifacts
    sign_artifacts

    # Verify artifacts
    verify_artifacts

    echo
    log_success "=== Build Complete ==="
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "This was a dry run. No actual builds were performed."
    fi
}

# Run main function
main "$@"


