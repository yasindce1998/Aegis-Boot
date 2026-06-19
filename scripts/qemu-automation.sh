#!/bin/bash
# QEMU Automation Script for Barzakh CI/CD Pipeline
# Automates: Build → Launch → Trigger → Dump → Scan → Report

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
DUMPS_DIR="$PROJECT_ROOT/dumps"
RESULTS_DIR="$PROJECT_ROOT/results"

# QEMU Configuration
QEMU_MEMORY="4G"
QEMU_CPUS="2"
QEMU_TIMEOUT=120
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Setup directories
setup_directories() {
    log_info "Setting up directories..."
    mkdir -p "$BUILD_DIR" "$DUMPS_DIR" "$RESULTS_DIR"
    mkdir -p "$DUMPS_DIR/memory" "$DUMPS_DIR/pcrs" "$DUMPS_DIR/eventlog"
}

# Build bootkit
build_bootkit() {
    log_info "Checking bootkit build status..."
    if [ ! -f "$BUILD_DIR/DxeInject.efi" ]; then
        log_warning "Bootkit not found, building..."
        cd "$PROJECT_ROOT"
        ./scripts/build.sh
        [ $? -ne 0 ] && log_error "Build failed" && exit 1
        log_success "Bootkit built successfully"
    else
        log_info "Using existing bootkit binary"
    fi
}

# Create disk image
create_disk_image() {
    log_info "Creating QEMU disk image..."
    DISK_IMAGE="$BUILD_DIR/test-disk.qcow2"
    if [ ! -f "$DISK_IMAGE" ]; then
        qemu-img create -f qcow2 "$DISK_IMAGE" 2G
        log_success "Disk image created"
    fi
}

# Prepare OVMF
prepare_ovmf_vars() {
    log_info "Preparing OVMF variables..."
    VARS_COPY="$BUILD_DIR/OVMF_VARS_test.fd"
    cp "$OVMF_VARS" "$VARS_COPY"
    log_success "OVMF variables prepared"
}

# Launch QEMU
launch_qemu() {
    log_info "Launching QEMU with bootkit..."
    
    DISK_IMAGE="$BUILD_DIR/test-disk.qcow2"
    VARS_COPY="$BUILD_DIR/OVMF_VARS_test.fd"
    MONITOR_SOCK="$BUILD_DIR/qemu-monitor.sock"
    SERIAL_LOG="$BUILD_DIR/serial.log"
    
    # Launch QEMU in background
    timeout $QEMU_TIMEOUT qemu-system-x86_64 \
        -machine q35,smm=on,accel=kvm:tcg \
        -cpu host \
        -m $QEMU_MEMORY \
        -smp $QEMU_CPUS \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$VARS_COPY" \
        -drive file="$DISK_IMAGE",format=qcow2 \
        -device swtpm-tpm-tis,tpmdev=tpm0 \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
        -monitor unix:"$MONITOR_SOCK",server,nowait \
        -serial file:"$SERIAL_LOG" \
        -nographic \
        -no-reboot &
    
    QEMU_PID=$!
    log_info "QEMU launched (PID: $QEMU_PID)"
    
    # Wait for boot
    sleep 30
    
    # Check if still running
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        log_error "QEMU exited prematurely"
        return 1
    fi
    
    log_success "QEMU running successfully"
    echo $QEMU_PID > "$BUILD_DIR/qemu.pid"
}

# Dump memory via QEMU monitor
dump_memory() {
    log_info "Dumping memory state..."
    
    MONITOR_SOCK="$BUILD_DIR/qemu-monitor.sock"
    MEMORY_DUMP="$DUMPS_DIR/memory/memory-$(date +%Y%m%d-%H%M%S).bin"
    
    # Use QEMU monitor to dump memory
    echo "pmemsave 0 0x100000000 $MEMORY_DUMP" | \
        socat - UNIX-CONNECT:"$MONITOR_SOCK"
    
    if [ -f "$MEMORY_DUMP" ]; then
        log_success "Memory dumped: $MEMORY_DUMP"
        echo "$MEMORY_DUMP" > "$DUMPS_DIR/latest_memory.txt"
    else
        log_error "Memory dump failed"
        return 1
    fi
}

# Dump PCR values
dump_pcrs() {
    log_info "Dumping TPM PCR values..."
    
    PCR_DUMP="$DUMPS_DIR/pcrs/pcrs-$(date +%Y%m%d-%H%M%S).json"
    
    # Read PCRs from swtpm
    swtpm_ioctl --unix /tmp/swtpm-sock -g > "$PCR_DUMP" 2>/dev/null || {
        log_warning "Could not read PCRs from TPM"
        echo '{"pcrs": {}}' > "$PCR_DUMP"
    }
    
    log_success "PCRs dumped: $PCR_DUMP"
    echo "$PCR_DUMP" > "$DUMPS_DIR/latest_pcrs.txt"
}

# Dump event log
dump_eventlog() {
    log_info "Dumping TCG event log..."
    
    EVENTLOG_DUMP="$DUMPS_DIR/eventlog/eventlog-$(date +%Y%m%d-%H%M%S).bin"
    SERIAL_LOG="$BUILD_DIR/serial.log"
    
    # Extract event log from serial output
    if [ -f "$SERIAL_LOG" ]; then
        grep "TCG_EVENT" "$SERIAL_LOG" > "$EVENTLOG_DUMP" || touch "$EVENTLOG_DUMP"
        log_success "Event log dumped: $EVENTLOG_DUMP"
    else
        log_warning "Serial log not found"
        touch "$EVENTLOG_DUMP"
    fi
    
    echo "$EVENTLOG_DUMP" > "$DUMPS_DIR/latest_eventlog.txt"
}

# Stop QEMU
stop_qemu() {
    log_info "Stopping QEMU..."
    
    if [ -f "$BUILD_DIR/qemu.pid" ]; then
        QEMU_PID=$(cat "$BUILD_DIR/qemu.pid")
        if kill -0 $QEMU_PID 2>/dev/null; then
            kill $QEMU_PID
            wait $QEMU_PID 2>/dev/null || true
            log_success "QEMU stopped"
        fi
        rm "$BUILD_DIR/qemu.pid"
    fi
}

# Run scanner
run_scanner() {
    log_info "Running Barzakh Scanner..."
    
    MEMORY_DUMP=$(cat "$DUMPS_DIR/latest_memory.txt")
    PCR_DUMP=$(cat "$DUMPS_DIR/latest_pcrs.txt")
    SCAN_RESULT="$RESULTS_DIR/scan-$(date +%Y%m%d-%H%M%S).json"
    
    python3 "$PROJECT_ROOT/src/BarzakhScanner/scanner.py" \
        "$MEMORY_DUMP" \
        --pcrs "$PCR_DUMP" \
        --output "$SCAN_RESULT" \
        --format json \
        --verbose
    
    if [ $? -eq 0 ]; then
        log_success "Scan completed: $SCAN_RESULT"
        echo "$SCAN_RESULT" > "$RESULTS_DIR/latest_scan.txt"
    else
        log_error "Scanner failed"
        return 1
    fi
}

# Generate report
generate_report() {
    log_info "Generating HTML report..."
    
    SCAN_RESULT=$(cat "$RESULTS_DIR/latest_scan.txt")
    HTML_REPORT="${SCAN_RESULT%.json}.html"
    
    python3 "$PROJECT_ROOT/src/BarzakhScanner/reports/report_generator.py" \
        "$SCAN_RESULT" \
        --format html \
        --output "$HTML_REPORT"
    
    if [ $? -eq 0 ]; then
        log_success "Report generated: $HTML_REPORT"
    else
        log_error "Report generation failed"
        return 1
    fi
}

# Validate results
validate_results() {
    log_info "Validating scan results..."
    
    SCAN_RESULT=$(cat "$RESULTS_DIR/latest_scan.txt")
    
    python3 "$PROJECT_ROOT/tests/validate_ci_results.py" "$SCAN_RESULT"
    
    if [ $? -eq 0 ]; then
        log_success "Validation passed"
        return 0
    else
        log_error "Validation failed"
        return 1
    fi
}

# Cleanup
cleanup() {
    log_info "Cleaning up..."
    stop_qemu
    rm -f /tmp/swtpm-sock
}

# Main execution
main() {
    log_info "Starting Barzakh CI/CD Pipeline"
    
    trap cleanup EXIT
    
    setup_directories
    build_bootkit
    create_disk_image
    prepare_ovmf_vars
    
    # Start swtpm
    mkdir -p /tmp/swtpm
    swtpm socket --tpmstate dir=/tmp/swtpm \
        --ctrl type=unixio,path=/tmp/swtpm-sock \
        --tpm2 --daemon
    
    launch_qemu
    sleep 10
    
    dump_memory
    dump_pcrs
    dump_eventlog
    
    stop_qemu
    
    run_scanner
    generate_report
    validate_results
    
    VALIDATION_RESULT=$?
    
    if [ $VALIDATION_RESULT -eq 0 ]; then
        log_success "Pipeline completed successfully"
        exit 0
    else
        log_error "Pipeline failed validation"
        exit 1
    fi
}

# Run main
main "$@"


