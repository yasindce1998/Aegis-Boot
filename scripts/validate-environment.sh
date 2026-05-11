#!/bin/bash
#
# Aegis-Boot Environment Validation Script
#
# This script validates that all prerequisites are met before beginning
# development or testing activities.
#
# USAGE:
#   ./validate-environment.sh [OPTIONS]
#
# OPTIONS:
#   --strict     Exit on first failure (default: report all issues)
#   --quiet      Minimal output (only errors)
#   --help       Show this help message

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source environment if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

# Configuration
STRICT_MODE=false
QUIET_MODE=false
FAILED_CHECKS=0
TOTAL_CHECKS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    if [[ "$QUIET_MODE" == "false" ]]; then
        echo -e "${BLUE}[INFO]${NC} $*"
    fi
}

log_success() {
    if [[ "$QUIET_MODE" == "false" ]]; then
        echo -e "${GREEN}[✓]${NC} $*"
    fi
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
}

# Check function wrapper
check() {
    local description="$1"
    local command="$2"
    
    ((TOTAL_CHECKS++))
    
    if [[ "$QUIET_MODE" == "false" ]]; then
        echo -n "Checking $description... "
    fi
    
    if eval "$command" &>/dev/null; then
        log_success "$description"
        return 0
    else
        log_error "$description"
        ((FAILED_CHECKS++))
        
        if [[ "$STRICT_MODE" == "true" ]]; then
            exit 1
        fi
        return 1
    fi
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --help)
                head -n 15 "$0" | grep "^#" | sed 's/^# \?//'
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Validation checks
validate_system_requirements() {
    log_info "=== System Requirements ==="
    
    # CPU virtualization
    check "CPU virtualization support" "egrep -c '(vmx|svm)' /proc/cpuinfo | grep -q '[1-9]'"
    
    # KVM availability
    check "KVM module loaded" "lsmod | grep -q kvm"
    
    # /dev/kvm access
    check "/dev/kvm accessible" "test -e /dev/kvm"
    
    # Memory (at least 8GB)
    check "Sufficient RAM (≥8GB)" "test $(free -g | awk '/^Mem:/{print $2}') -ge 8"
    
    # Disk space (at least 50GB free)
    check "Sufficient disk space (≥50GB)" "test $(df -BG . | awk 'NR==2{print $4}' | sed 's/G//') -ge 50"
    
    echo
}

validate_software_dependencies() {
    log_info "=== Software Dependencies ==="
    
    # Core tools
    check "GCC compiler" "command -v gcc"
    check "GCC version ≥11.0" "test $(gcc -dumpversion | cut -d. -f1) -ge 11"
    check "Python 3" "command -v python3"
    check "Python version ≥3.10" "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'"
    check "Git" "command -v git"
    check "Make" "command -v make"
    check "NASM assembler" "command -v nasm"
    check "IASL compiler" "command -v iasl"
    
    # QEMU
    check "QEMU" "command -v qemu-system-x86_64"
    check "QEMU version ≥7.0" "qemu-system-x86_64 --version | grep -oP 'version \K[0-9]+' | head -1 | awk '{exit ($1 >= 7) ? 0 : 1}'"
    
    # vTPM
    check "swtpm" "command -v swtpm"
    
    # Security tools
    check "GPG" "command -v gpg"
    
    echo
}

validate_edk2_environment() {
    log_info "=== EDK II Environment ==="
    
    local workspace="${WORKSPACE:-$HOME/aegis-workspace/edk2}"
    
    # EDK II workspace
    check "EDK II workspace exists" "test -d '$workspace'"
    check "EDK II edksetup.sh" "test -f '$workspace/edksetup.sh'"
    check "EDK II BaseTools" "test -d '$workspace/BaseTools'"
    check "BaseTools compiled" "test -f '$workspace/BaseTools/Source/C/bin/GenFw'"
    
    # OVMF
    local ovmf_code="${OVMF_CODE:-$workspace/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd}"
    local ovmf_vars="${OVMF_VARS:-$workspace/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd}"
    
    check "OVMF_CODE.fd exists" "test -f '$ovmf_code'"
    check "OVMF_VARS.fd exists" "test -f '$ovmf_vars'"
    
    echo
}

validate_project_structure() {
    log_info "=== Project Structure ==="
    
    # Required directories
    check "docs/ directory" "test -d '$PROJECT_ROOT/docs'"
    check "src/ directory" "test -d '$PROJECT_ROOT/src'"
    check "scripts/ directory" "test -d '$PROJECT_ROOT/scripts'"
    check "test/ directory" "test -d '$PROJECT_ROOT/test'"
    
    # Required files
    check "README.md" "test -f '$PROJECT_ROOT/README.md'"
    check "draft.md" "test -f '$PROJECT_ROOT/draft.md'"
    check "technical_details.md" "test -f '$PROJECT_ROOT/technical_details.md'"
    check "testing.md" "test -f '$PROJECT_ROOT/testing.md'"
    
    # Scripts
    check "build.sh" "test -f '$PROJECT_ROOT/scripts/build.sh'"
    check "qemu-run.sh" "test -f '$PROJECT_ROOT/scripts/qemu-run.sh'"
    check "audit-log.sh" "test -f '$PROJECT_ROOT/scripts/audit-log.sh'"
    check "nvram-recovery.py" "test -f '$PROJECT_ROOT/scripts/nvram-recovery.py'"
    
    echo
}

validate_security_configuration() {
    log_info "=== Security Configuration ==="
    
    # Environment variables
    check "IRB_APPROVAL_DATE set" "test -n '${IRB_APPROVAL_DATE:-}'"
    
    if [[ -n "${IRB_APPROVAL_DATE:-}" ]]; then
        check "IRB_APPROVAL_DATE valid format" "date -d '$IRB_APPROVAL_DATE' &>/dev/null"
        
        # Check if approval is not expired (within 36 months)
        local approval_epoch=$(date -d "$IRB_APPROVAL_DATE" +%s 2>/dev/null || echo 0)
        local current_epoch=$(date +%s)
        local max_validity=$((36 * 30 * 24 * 60 * 60))
        
        if [[ $approval_epoch -gt 0 ]]; then
            check "IRB approval not expired" "test $((current_epoch - approval_epoch)) -le $max_validity"
        fi
    fi
    
    check "AEGIS_ALLOWED_UUID set" "test -n '${AEGIS_ALLOWED_UUID:-}'"
    check "AEGIS_EXPIRY_DATE set" "test -n '${AEGIS_EXPIRY_DATE:-}'"
    
    # Git configuration
    check "Git user.name configured" "git config user.name &>/dev/null"
    check "Git user.email configured" "git config user.email &>/dev/null"
    check "Git commit signing enabled" "git config commit.gpgsign | grep -q true"
    
    # GPG key
    if git config user.signingkey &>/dev/null; then
        local key_id=$(git config user.signingkey)
        check "GPG signing key available" "gpg --list-secret-keys '$key_id' &>/dev/null"
    else
        log_warning "Git signing key not configured (user.signingkey)"
    fi
    
    echo
}

validate_audit_logging() {
    log_info "=== Audit Logging ==="
    
    local audit_dir="${AUDIT_LOG_DIR:-$PROJECT_ROOT/docs/audit}"
    
    check "Audit log directory exists" "test -d '$audit_dir'"
    check "Audit log directory writable" "test -w '$audit_dir'"
    
    # Test audit logging
    if [[ -f "$PROJECT_ROOT/scripts/audit-log.sh" ]]; then
        check "Audit logging functional" "bash '$PROJECT_ROOT/scripts/audit-log.sh' --event-type TEST 'Environment validation test' &>/dev/null"
    fi
    
    echo
}

validate_vtpm_setup() {
    log_info "=== vTPM Configuration ==="
    
    local vtpm_dir="${VTPM_STATE_DIR:-$HOME/aegis-workspace/vtpm-state}"
    
    check "vTPM state directory exists" "test -d '$vtpm_dir' || mkdir -p '$vtpm_dir'"
    check "vTPM state directory writable" "test -w '$vtpm_dir'"
    
    # Check if swtpm can start
    check "swtpm can initialize" "swtpm socket --tpmstate dir='$vtpm_dir' --ctrl type=unixio,path='$vtpm_dir/test-sock' --tpm2 --daemon && sleep 1 && pkill -f 'swtpm.*test-sock' && rm -f '$vtpm_dir/test-sock'"
    
    echo
}

# Generate report
generate_report() {
    echo
    echo "=== Validation Summary ==="
    echo "Total checks: $TOTAL_CHECKS"
    echo "Passed: $((TOTAL_CHECKS - FAILED_CHECKS))"
    echo "Failed: $FAILED_CHECKS"
    echo
    
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        log_success "All validation checks passed!"
        echo
        log_info "You can proceed with:"
        log_info "  1. Building packages: ./scripts/build.sh"
        log_info "  2. Running tests: ./scripts/qemu-run.sh --test-mode"
        log_info "  3. See docs/SETUP.md for detailed instructions"
        return 0
    else
        log_error "$FAILED_CHECKS validation check(s) failed"
        echo
        log_info "Please address the failed checks before proceeding."
        log_info "See docs/SETUP.md for detailed setup instructions."
        return 1
    fi
}

# Main function
main() {
    parse_args "$@"
    
    echo "=== Aegis-Boot Environment Validation ==="
    echo
    
    validate_system_requirements
    validate_software_dependencies
    validate_edk2_environment
    validate_project_structure
    validate_security_configuration
    validate_audit_logging
    validate_vtpm_setup
    
    generate_report
}

# Run main function
main "$@"

# Made with Bob
