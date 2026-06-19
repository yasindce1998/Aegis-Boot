#!/bin/bash
#
# Dump TPM PCR Values
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -e

SWTPM_SOCKET="${SWTPM_SOCKET:-/tmp/swtpm-sock}"
OUTPUT_FILE="${1:-pcrs.json}"

# Check if swtpm is available
if ! command -v tpm2_pcrread &> /dev/null; then
    echo "[ERROR] tpm2_pcrread not found. Install tpm2-tools" >&2
    exit 1
fi

# Read PCR values
echo "[*] Reading TPM PCR values..." >&2

# Create JSON output
cat > "${OUTPUT_FILE}" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcrs": {
EOF

# Read PCRs 0-23
for pcr in {0..23}; do
    value=$(tpm2_pcrread "sha256:${pcr}" 2>/dev/null | grep "sha256" | awk '{print $3}' || echo "0000000000000000000000000000000000000000000000000000000000000000")
    
    if [ $pcr -lt 23 ]; then
        echo "    \"${pcr}\": \"${value}\"," >> "${OUTPUT_FILE}"
    else
        echo "    \"${pcr}\": \"${value}\"" >> "${OUTPUT_FILE}"
    fi
done

cat >> "${OUTPUT_FILE}" << EOF
  }
}
EOF

echo "[+] PCR values dumped to ${OUTPUT_FILE}" >&2
cat "${OUTPUT_FILE}"


