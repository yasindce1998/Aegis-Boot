#!/bin/bash
#
# Dump QEMU Memory State
#
# Copyright (c) 2026, Aegis-Boot Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -e

QEMU_MONITOR_PORT="${QEMU_MONITOR_PORT:-55555}"
OUTPUT_FILE="${1:-memory-dump.bin}"

# Check if QEMU is running
if ! pgrep -f "qemu-system-x86_64" > /dev/null; then
    echo "[ERROR] QEMU is not running" >&2
    exit 1
fi

# Dump memory via QEMU monitor
echo "[*] Dumping memory from QEMU..." >&2
echo "pmemsave 0 0x100000000 ${OUTPUT_FILE}" | nc localhost "${QEMU_MONITOR_PORT}" || {
    echo "[ERROR] Failed to dump memory" >&2
    exit 1
}

echo "[+] Memory dumped to ${OUTPUT_FILE}" >&2
cat "${OUTPUT_FILE}"

# Made with Bob
