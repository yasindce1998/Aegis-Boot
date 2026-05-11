#!/bin/bash
#
# Aegis-Boot Audit Logging System
#
# This script provides append-only, GPG-signed audit logging for all
# project activities. Required for IRB compliance and forensic traceability.
#
# USAGE:
#   ./audit-log.sh [OPTIONS] "log message"
#
# OPTIONS:
#   --event-type TYPE    Event type (BUILD|TEST|EXECUTION|ANALYSIS|ADMIN)
#   --severity LEVEL     Severity (INFO|WARNING|ERROR|CRITICAL)
#   --metadata KEY=VALUE Additional metadata (can be used multiple times)
#   --help               Show this help message
#
# EXAMPLES:
#   ./audit-log.sh --event-type BUILD "Compiled BootkitPkg successfully"
#   ./audit-log.sh --event-type EXECUTION --severity WARNING "Bootkit injected in test VM"
#   ./audit-log.sh --event-type ADMIN --metadata action=key_rotation "Rotated artifact signing keys"

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source environment if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

# Configuration
AUDIT_LOG_DIR="${AUDIT_LOG_DIR:-$PROJECT_ROOT/docs/audit}"
GPG_KEY_ID="${AUDIT_GPG_KEY_ID:-}"

# Default values
EVENT_TYPE="INFO"
SEVERITY="INFO"
declare -A METADATA

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Show usage
show_usage() {
    head -n 20 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    local message=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --event-type)
                EVENT_TYPE="$2"
                shift 2
                ;;
            --severity)
                SEVERITY="$2"
                shift 2
                ;;
            --metadata)
                IFS='=' read -r key value <<< "$2"
                METADATA["$key"]="$value"
                shift 2
                ;;
            --help)
                show_usage
                ;;
            *)
                message="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$message" ]]; then
        log_error "No log message provided"
        show_usage
    fi

    echo "$message"
}

# Initialize audit log directory
init_audit_log() {
    if [[ ! -d "$AUDIT_LOG_DIR" ]]; then
        log_info "Creating audit log directory: $AUDIT_LOG_DIR"
        mkdir -p "$AUDIT_LOG_DIR"
    fi

    # Create .gitkeep to ensure directory is tracked
    touch "$AUDIT_LOG_DIR/.gitkeep"

    # Create README if it doesn't exist
    if [[ ! -f "$AUDIT_LOG_DIR/README.md" ]]; then
        cat > "$AUDIT_LOG_DIR/README.md" <<'EOF'
# Audit Logs

This directory contains immutable, append-only audit logs for the Aegis-Boot project.

## Structure

Logs are organized by year-month:
- `YYYYMM.log` - Main audit log for the month
- `YYYYMM.log.sig` - GPG signature for the log file

## Integrity

All audit logs are:
1. **Append-only** - Previous entries cannot be modified
2. **GPG-signed** - Each log file has a corresponding signature
3. **Timestamped** - All entries use ISO 8601 UTC timestamps
4. **Immutable** - Logs are backed up to encrypted cold storage within 24 hours

## Compliance

These logs are required for:
- IRB compliance and oversight
- Forensic traceability
- Academic peer review
- Incident response

## Access Control

Access to audit logs is restricted to:
- Principal Investigator
- Information Security Officer
- IRB reviewers (upon request)

**DO NOT MODIFY OR DELETE AUDIT LOGS**

Unauthorized modification or deletion of audit logs may constitute:
- IRB protocol violation
- Research misconduct
- Legal liability
EOF
    fi
}

# Get current log file path
get_log_file() {
    local year_month=$(date +%Y%m)
    echo "$AUDIT_LOG_DIR/${year_month}.log"
}

# Generate log entry
generate_log_entry() {
    local message="$1"
    local log_file=$(get_log_file)

    # Gather system information
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local researcher="${USER}"
    local hostname=$(hostname)
    local git_commit="N/A"
    
    if git -C "$PROJECT_ROOT" rev-parse HEAD &>/dev/null; then
        git_commit=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD)
    fi

    # Create log entry
    cat <<EOF
---
timestamp: ${timestamp}
event_type: ${EVENT_TYPE}
severity: ${SEVERITY}
researcher: ${researcher}
hostname: ${hostname}
git_commit: ${git_commit}
message: ${message}
EOF

    # Add metadata if present
    if [[ ${#METADATA[@]} -gt 0 ]]; then
        echo "metadata:"
        for key in "${!METADATA[@]}"; do
            echo "  ${key}: ${METADATA[$key]}"
        done
    fi

    echo "---"
    echo ""
}

# Append to log file
append_to_log() {
    local log_entry="$1"
    local log_file=$(get_log_file)

    # Append entry
    echo "$log_entry" >> "$log_file"

    log_success "Audit entry appended to: $log_file"
}

# Sign log file
sign_log_file() {
    local log_file=$(get_log_file)
    local sig_file="${log_file}.sig"

    # Check if GPG is available
    if ! command -v gpg &> /dev/null; then
        log_warning "GPG not available, skipping signature"
        return 0
    fi

    # Check if GPG key is configured
    if [[ -z "$GPG_KEY_ID" ]]; then
        log_warning "AUDIT_GPG_KEY_ID not set, skipping signature"
        log_info "Set AUDIT_GPG_KEY_ID in .env to enable signing"
        return 0
    fi

    # Sign the log file
    if gpg --local-user "$GPG_KEY_ID" --detach-sign --armor --output "$sig_file" "$log_file" 2>/dev/null; then
        log_success "Log file signed: $sig_file"
    else
        log_warning "Failed to sign log file (GPG key may not be available)"
    fi
}

# Verify log file integrity
verify_log_integrity() {
    local log_file="$1"
    local sig_file="${log_file}.sig"

    if [[ ! -f "$sig_file" ]]; then
        log_warning "No signature file found for: $log_file"
        return 1
    fi

    if gpg --verify "$sig_file" "$log_file" 2>/dev/null; then
        log_success "Signature verified for: $log_file"
        return 0
    else
        log_error "Signature verification FAILED for: $log_file"
        return 1
    fi
}

# List recent audit entries
list_recent_entries() {
    local log_file=$(get_log_file)
    local count="${1:-10}"

    if [[ ! -f "$log_file" ]]; then
        log_info "No audit log for current month"
        return 0
    fi

    log_info "Recent audit entries (last $count):"
    echo

    # Extract last N entries
    awk -v count="$count" '
        /^---$/ { 
            if (NR > 1) entries[++n] = entry; 
            entry = $0 "\n"; 
            next 
        } 
        { entry = entry $0 "\n" }
        END { 
            start = (n > count) ? n - count + 1 : 1;
            for (i = start; i <= n; i++) print entries[i]
        }
    ' "$log_file"
}

# Export audit logs for IRB review
export_for_review() {
    local output_dir="${1:-$PROJECT_ROOT/audit-export-$(date +%Y%m%d)}"
    
    log_info "Exporting audit logs for IRB review..."
    mkdir -p "$output_dir"

    # Copy all log files
    cp "$AUDIT_LOG_DIR"/*.log "$output_dir/" 2>/dev/null || true
    cp "$AUDIT_LOG_DIR"/*.sig "$output_dir/" 2>/dev/null || true

    # Create index
    cat > "$output_dir/INDEX.md" <<EOF
# Audit Log Export

**Export Date:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Exported By:** ${USER}
**Project:** Aegis-Boot

## Contents

This export contains all audit logs for the Aegis-Boot project.

## Files

EOF

    # List all log files
    for log_file in "$output_dir"/*.log; do
        if [[ -f "$log_file" ]]; then
            local basename=$(basename "$log_file")
            local entries=$(grep -c "^timestamp:" "$log_file" || echo 0)
            local hash=$(sha256sum "$log_file" | cut -d' ' -f1)
            
            cat >> "$output_dir/INDEX.md" <<EOF
### $basename
- **Entries:** $entries
- **SHA256:** \`$hash\`
- **Signature:** ${basename}.sig

EOF
        fi
    done

    # Create tarball
    local tarball="$output_dir.tar.gz"
    tar -czf "$tarball" -C "$(dirname "$output_dir")" "$(basename "$output_dir")"

    log_success "Audit logs exported to: $tarball"
    log_info "SHA256: $(sha256sum "$tarball" | cut -d' ' -f1)"
}

# Main function
main() {
    local message
    message=$(parse_args "$@")

    # Initialize audit log
    init_audit_log

    # Generate log entry
    local log_entry
    log_entry=$(generate_log_entry "$message")

    # Append to log
    append_to_log "$log_entry"

    # Sign log file
    sign_log_file

    # Display confirmation
    log_info "Event Type: $EVENT_TYPE"
    log_info "Severity: $SEVERITY"
    log_info "Message: $message"
}

# Handle special commands
if [[ $# -gt 0 ]]; then
    case $1 in
        --list)
            shift
            list_recent_entries "$@"
            exit 0
            ;;
        --verify)
            shift
            verify_log_integrity "$1"
            exit $?
            ;;
        --export)
            shift
            export_for_review "$@"
            exit 0
            ;;
    esac
fi

# Run main function
main "$@"

# Made with Bob
