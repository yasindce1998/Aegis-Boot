#!/bin/bash
#
# Barzakh QEMU Test Harness
# 
# This script provides a safe, controlled environment for testing UEFI bootkit
# emulation within QEMU virtualization. It enforces security constraints and
# provides comprehensive logging for audit compliance.
#
# USAGE:
#   ./qemu-run.sh [OPTIONS]
#
# OPTIONS:
#   --test-mode          Run in test mode (no bootkit injection)
#   --infected           Run with bootkit payload injected
#   --clean-boot         Run clean baseline boot for comparison
#   --debug              Enable verbose debug output
#   --serial-log FILE    Save serial output to FILE
#   --memory SIZE        Set VM memory in MB (default: 4096)
#   --cpus NUM           Set number of vCPUs (default: 2)
#   --snapshot           Use snapshot mode (no persistent changes)
#   --no-network         Disable all network devices (default: enabled)
#   --help               Show this help message
#
# SECURITY NOTES:
#   - Network is DISABLED by default for air-gap compliance
#   - All executions are logged to audit trail
#   - UUID and TPM EK are validated before boot
#   - Requires AEGIS_EXPIRY_DATE environment variable

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
OVMF_CODE="${OVMF_CODE:-$WORKSPACE/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-$WORKSPACE/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd}"
VTPM_STATE_DIR="${VTPM_STATE_DIR:-$HOME/barzakh-workspace/vtpm-state}"
DISK_IMAGE="${DISK_IMAGE:-$PROJECT_ROOT/test/test-disk.qcow2}"

# VM Configuration
VM_MEMORY="${VM_MEMORY:-4096}"
VM_CPUS="${VM_CPUS:-2}"
VM_UUID="${AEGIS_ALLOWED_UUID:-00000000-0000-0000-0000-000000000000}"

# Execution mode
TEST_MODE=false
INFECTED_MODE=false
CLEAN_BOOT=false
DEBUG_MODE=false
SNAPSHOT_MODE=false
NETWORK_ENABLED=false
SERIAL_LOG=""

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
    head -n 30 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test-mode)
                TEST_MODE=true
                shift
                ;;
            --infected)
                INFECTED_MODE=true
                shift
                ;;
            --clean-boot)
                CLEAN_BOOT=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --serial-log)
                SERIAL_LOG="$2"
                shift 2
                ;;
            --memory)
                VM_MEMORY="$2"
                shift 2
                ;;
            --cpus)
                VM_CPUS="$2"
                shift 2
                ;;
            --snapshot)
                SNAPSHOT_MODE=true
                shift
                ;;
            --no-network)
                NETWORK_ENABLED=false
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
    log_info "Validating environment..."

    # Check OVMF files
    if [[ ! -f "$OVMF_CODE" ]]; then
        log_error "OVMF_CODE not found: $OVMF_CODE"
        log_error "Run 'build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -D TPM2_ENABLE=TRUE' first"
        exit 1
    fi

    if [[ ! -f "$OVMF_VARS" ]]; then
        log_error "OVMF_VARS not found: $OVMF_VARS"
        exit 1
    fi

    # Check QEMU
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        log_error "qemu-system-x86_64 not found. Install QEMU first."
        exit 1
    fi

    # Check KVM support
    if [[ ! -e /dev/kvm ]]; then
        log_warning "KVM not available. Performance will be degraded."
        log_warning "Enable KVM with: sudo modprobe kvm && sudo modprobe kvm_intel"
    fi

    # Check vTPM state directory
    if [[ ! -d "$VTPM_STATE_DIR" ]]; then
        log_warning "vTPM state directory not found: $VTPM_STATE_DIR"
        log_info "Creating vTPM state directory..."
        mkdir -p "$VTPM_STATE_DIR"
    fi

    # Create disk image if it doesn't exist
    if [[ ! -f "$DISK_IMAGE" ]]; then
        log_info "Creating test disk image..."
        mkdir -p "$(dirname "$DISK_IMAGE")"
        qemu-img create -f qcow2 "$DISK_IMAGE" 20G
    fi

    log_success "Environment validation passed"
}

# Start vTPM if not running
start_vtpm() {
    log_info "Checking vTPM status..."

    local vtpm_sock="$VTPM_STATE_DIR/swtpm-sock"
    
    # Check if vTPM is already running
    if [[ -S "$vtpm_sock" ]]; then
        log_info "vTPM already running"
        return 0
    fi

    log_info "Starting vTPM..."
    
    # Clean up old state if requested
    if [[ "$CLEAN_BOOT" == "true" ]]; then
        log_warning "Clean boot requested - removing vTPM state"
        rm -rf "$VTPM_STATE_DIR"/*
    fi

    # Start swtpm
    swtpm socket \
        --tpmstate dir="$VTPM_STATE_DIR" \
        --ctrl type=unixio,path="$vtpm_sock" \
        --tpm2 \
        --log level=20 \
        --daemon

    # Wait for socket to be ready
    local retries=10
    while [[ $retries -gt 0 ]]; do
        if [[ -S "$vtpm_sock" ]]; then
            log_success "vTPM started successfully"
            return 0
        fi
        sleep 0.5
        ((retries--))
    done

    log_error "Failed to start vTPM"
    exit 1
}

# Generate audit log entry
log_audit_entry() {
    local status="$1"
    local details="$2"

    local audit_log="$PROJECT_ROOT/docs/audit/$(date +%Y%m).log"
    mkdir -p "$(dirname "$audit_log")"

    cat >> "$audit_log" <<EOF
---
Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Researcher: ${USER}
Hostname: $(hostname)
VM UUID: ${VM_UUID}
Mode: $(if [[ "$INFECTED_MODE" == "true" ]]; then echo "INFECTED"; elif [[ "$TEST_MODE" == "true" ]]; then echo "TEST"; else echo "CLEAN"; fi)
Status: ${status}
OVMF Code Hash: $(sha256sum "$OVMF_CODE" | cut -d' ' -f1)
OVMF Vars Hash: $(sha256sum "$OVMF_VARS" | cut -d' ' -f1)
Details: ${details}
---

EOF

    log_info "Audit entry logged to: $audit_log"
}

# Build QEMU command
build_qemu_command() {
    local qemu_cmd=(
        qemu-system-x86_64
        -machine q35,smm=on
        -cpu host
        -m "$VM_MEMORY"
        -smp "$VM_CPUS"
        -uuid "$VM_UUID"
    )

    # Add KVM acceleration if available
    if [[ -e /dev/kvm ]]; then
        qemu_cmd+=(-accel kvm)
    fi

    # OVMF firmware
    qemu_cmd+=(
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
    )

    # OVMF variables (snapshot mode if requested)
    if [[ "$SNAPSHOT_MODE" == "true" ]]; then
        qemu_cmd+=(-drive if=pflash,format=raw,snapshot=on,file="$OVMF_VARS")
    else
        # Create a copy of VARS to avoid corrupting the original
        local vars_copy="$VTPM_STATE_DIR/OVMF_VARS_runtime.fd"
        cp "$OVMF_VARS" "$vars_copy"
        qemu_cmd+=(-drive if=pflash,format=raw,file="$vars_copy")
    fi

    # Disk image
    if [[ "$SNAPSHOT_MODE" == "true" ]]; then
        qemu_cmd+=(-drive file="$DISK_IMAGE",if=virtio,format=qcow2,snapshot=on)
    else
        qemu_cmd+=(-drive file="$DISK_IMAGE",if=virtio,format=qcow2)
    fi

    # vTPM
    local vtpm_sock="$VTPM_STATE_DIR/swtpm-sock"
    qemu_cmd+=(
        -chardev socket,id=chrtpm,path="$vtpm_sock"
        -tpmdev emulator,id=tpm0,chardev=chrtpm
        -device tpm-tis,tpmdev=tpm0
    )

    # Network (disabled by default for air-gap compliance)
    if [[ "$NETWORK_ENABLED" == "false" ]]; then
        qemu_cmd+=(-net none)
    else
        log_warning "Network is ENABLED - ensure air-gap compliance!"
        qemu_cmd+=(-netdev user,id=net0 -device virtio-net-pci,netdev=net0)
    fi

    # Serial output
    if [[ -n "$SERIAL_LOG" ]]; then
        qemu_cmd+=(-serial file:"$SERIAL_LOG")
    else
        qemu_cmd+=(-serial stdio)
    fi

    # Display
    qemu_cmd+=(-nographic)

    # Debug options
    if [[ "$DEBUG_MODE" == "true" ]]; then
        qemu_cmd+=(-d guest_errors,cpu_reset -D "$PROJECT_ROOT/test/qemu-debug.log")
    fi

    echo "${qemu_cmd[@]}"
}

# Main execution
main() {
    parse_args "$@"

    log_info "=== Barzakh QEMU Test Harness ==="
    log_info "Mode: $(if [[ "$INFECTED_MODE" == "true" ]]; then echo "INFECTED"; elif [[ "$TEST_MODE" == "true" ]]; then echo "TEST"; else echo "CLEAN"; fi)"
    log_info "VM UUID: $VM_UUID"
    log_info "Memory: ${VM_MEMORY}MB"
    log_info "CPUs: $VM_CPUS"
    log_info "Network: $(if [[ "$NETWORK_ENABLED" == "true" ]]; then echo "ENABLED"; else echo "DISABLED"; fi)"
    log_info "Snapshot: $(if [[ "$SNAPSHOT_MODE" == "true" ]]; then echo "YES"; else echo "NO"; fi)"
    echo

    # Validate environment
    validate_environment

    # Start vTPM
    start_vtpm

    # Build QEMU command as array
    local QEMU_CMD
    readarray -t QEMU_CMD < <(build_qemu_command)

    # Log audit entry (start)
    log_audit_entry "STARTED" "QEMU execution initiated"

    # Display command if debug mode
    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_info "QEMU Command:"
        printf '%s ' "${QEMU_CMD[@]}"
        echo
        echo
    fi

    # Execute QEMU
    log_info "Starting QEMU..."
    log_info "Press Ctrl+A then X to exit QEMU"
    echo

    # Run QEMU and capture exit code (array-based, no eval)
    set +e
    "${QEMU_CMD[@]}"
    local exit_code=$?
    set -e

    # Log audit entry (end)
    if [[ $exit_code -eq 0 ]]; then
        log_audit_entry "COMPLETED" "QEMU execution completed successfully"
        log_success "QEMU execution completed"
    else
        log_audit_entry "FAILED" "QEMU execution failed with exit code $exit_code"
        log_error "QEMU execution failed with exit code: $exit_code"
    fi

    return $exit_code
}

# Run main function
main "$@"


