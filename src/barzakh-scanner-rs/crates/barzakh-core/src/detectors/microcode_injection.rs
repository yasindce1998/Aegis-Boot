use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Intel MCU header magic: header_version field = 1 (u32 LE)
const INTEL_MCU_MAGIC: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
// Intel MCU header is 48 bytes; data_size threshold for "abnormally large"
const INTEL_MCU_HEADER_SIZE: usize = 48;
const INTEL_MCU_MAX_DATA_SIZE: u32 = 0x4000; // 16 KB
                                             // AMD microcode container starts with 4 zero bytes
const AMD_MCU_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const AMD_MCU_MAX_TABLE_SIZE: u32 = 0x2000;
// Intel FIT table signature bytes (precede legitimate MCU references)
const FIT_MAGIC: [u8; 4] = [0x5F, 0x46, 0x49, 0x54]; // "_FIT"
const FIT_SEARCH_WINDOW: usize = 4096;

pub struct MicrocodeInjectionDetector;

impl Default for MicrocodeInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MicrocodeInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check whether a 3-byte BCD date field (stored as a u32, lower 3 bytes) is valid.
    /// Intel date format is 0xMMDDYYYY in BCD.
    fn is_valid_bcd_date(date: u32) -> bool {
        // Extract BCD nibbles
        let month_hi = (date >> 28) & 0xF;
        let month_lo = (date >> 24) & 0xF;
        let day_hi = (date >> 20) & 0xF;
        let day_lo = (date >> 16) & 0xF;
        let year_hi = (date >> 12) & 0xF;
        let year_lo = (date >> 8) & 0xF;
        let year_lo2 = (date >> 4) & 0xF;
        let year_lo3 = date & 0xF;

        // All nibbles must be 0–9 (valid BCD)
        let nibbles = [
            month_hi, month_lo, day_hi, day_lo, year_hi, year_lo, year_lo2, year_lo3,
        ];
        if nibbles.iter().any(|&n| n > 9) {
            return false;
        }

        let month = month_hi * 10 + month_lo;
        let day = day_hi * 10 + day_lo;

        (1..=12).contains(&month) && (1..=31).contains(&day)
    }

    /// Scan for Intel MCU headers at 48-byte-aligned offsets.
    fn check_intel_mcu_headers(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut offset = 0usize;
        while offset + INTEL_MCU_HEADER_SIZE <= data.len() {
            // Intel MCU header_version == 1 at aligned offsets
            if data[offset..offset + 4] == INTEL_MCU_MAGIC {
                // Parse header fields (all u32 LE)
                let read_u32 = |o: usize| -> u32 {
                    u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
                };

                let _update_revision = read_u32(offset + 4);
                let date = read_u32(offset + 8);
                let processor_signature = read_u32(offset + 12);
                let _checksum = read_u32(offset + 16);
                let _loader_revision = read_u32(offset + 20);
                let _processor_flags = read_u32(offset + 24);
                let data_size = read_u32(offset + 28);
                let total_size = read_u32(offset + 32);

                // Validate: total_size should equal data_size + 48
                let expected_total = data_size.saturating_add(INTEL_MCU_HEADER_SIZE as u32);
                let oversized = data_size > INTEL_MCU_MAX_DATA_SIZE;
                let size_mismatch = total_size != expected_total && total_size != 0;
                let bad_date = !Self::is_valid_bcd_date(date);

                if oversized || size_mismatch || bad_date {
                    let severity = if oversized {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let reason = match (oversized, size_mismatch, bad_date) {
                        (true, _, _) => {
                            format!("data_size 0x{:X} exceeds 16 KB threshold", data_size)
                        }
                        (_, true, _) => format!(
                            "total_size 0x{:X} != data_size 0x{:X} + 48",
                            total_size, data_size
                        ),
                        _ => format!("invalid BCD date field 0x{:08X}", date),
                    };

                    findings.push(
                        Finding::new(
                            "microcode_injection",
                            severity,
                            "Suspicious Intel MCU header detected",
                            &format!(
                                "Intel MCU header at offset 0x{:08X} has anomalous fields: {}. \
                                 Processor signature: 0x{:08X}. Tampered or injected microcode \
                                 updates can subvert CPU security guarantees.",
                                offset, reason, processor_signature
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", offset),
                            "data_size": format!("0x{:X}", data_size),
                            "total_size": format!("0x{:X}", total_size),
                            "date": format!("0x{:08X}", date),
                            "processor_signature": format!("0x{:08X}", processor_signature),
                            "oversized": oversized,
                            "size_mismatch": size_mismatch,
                            "bad_date": bad_date,
                        }))
                        .with_recommendation(
                            "Verify all CPU microcode updates against vendor-signed capsules. \
                             Reject firmware images containing unsigned or malformed MCU headers.",
                        ),
                    );
                }
            }

            offset += INTEL_MCU_HEADER_SIZE;
        }

        findings
    }

    /// Look for AMD microcode container: 4 zero bytes then table_size.
    fn check_amd_equiv_table(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(12) {
            if data[i..i + 4] == AMD_MCU_MAGIC {
                // Next u32 LE = table_size
                let table_size =
                    u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);

                if table_size == 0 {
                    continue;
                }

                let suspicious_size = table_size > AMD_MCU_MAX_TABLE_SIZE;

                // Check entries within the table for processor_id==0 but equiv_id!=0
                // Each entry is 10 bytes: processor_id(u32), patch_id(u32), equiv_id(u16)
                let table_end = (i + 8 + table_size as usize).min(data.len());
                let table_data = &data[(i + 8).min(data.len())..table_end];

                let mut null_proc_nonzero_equiv = false;
                let mut entry_off = 0usize;
                while entry_off + 10 <= table_data.len() {
                    let proc_id = u32::from_le_bytes([
                        table_data[entry_off],
                        table_data[entry_off + 1],
                        table_data[entry_off + 2],
                        table_data[entry_off + 3],
                    ]);
                    let equiv_id =
                        u16::from_le_bytes([table_data[entry_off + 8], table_data[entry_off + 9]]);
                    if proc_id == 0 && equiv_id != 0 {
                        null_proc_nonzero_equiv = true;
                        break;
                    }
                    entry_off += 10;
                }

                if suspicious_size || null_proc_nonzero_equiv {
                    let reason = if suspicious_size {
                        format!("table_size 0x{:X} exceeds 0x2000", table_size)
                    } else {
                        "entry has processor_id=0 with non-zero equiv_id".to_string()
                    };

                    findings.push(
                        Finding::new(
                            "microcode_injection",
                            Severity::High,
                            "Suspicious AMD microcode equivalence table",
                            &format!(
                                "AMD microcode container at offset 0x{:08X} has anomalous \
                                 equivalence table: {}. This may indicate a tampered or injected \
                                 AMD CPU microcode update.",
                                i, reason
                            ),
                        )
                        .with_confidence(0.80)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "table_size": format!("0x{:X}", table_size),
                            "suspicious_size": suspicious_size,
                            "null_proc_nonzero_equiv": null_proc_nonzero_equiv,
                        }))
                        .with_recommendation(
                            "Validate AMD microcode containers against AMD vendor signatures. \
                             Check PSP-signed update capsule integrity.",
                        ),
                    );
                }
            }
        }

        findings
    }

    /// Detect MCU magic or "microcode" string outside of standard FIT-table regions.
    fn check_unexpected_microcode_location(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let needle_str = b"microcode";

        // Collect string occurrences
        for i in 0..data.len().saturating_sub(needle_str.len()) {
            let window = &data[i..i + needle_str.len()];
            let matched_str = window.eq_ignore_ascii_case(needle_str);

            // Also match Intel MCU magic at non-48-byte-aligned positions
            let matched_mcu = i % INTEL_MCU_HEADER_SIZE != 0
                && i + 4 <= data.len()
                && data[i..i + 4] == INTEL_MCU_MAGIC;

            if !matched_str && !matched_mcu {
                continue;
            }

            // Check whether a FIT table signature exists within 4KB before this offset
            let search_start = i.saturating_sub(FIT_SEARCH_WINDOW);
            let preceding = &data[search_start..i];
            let fit_present = preceding.windows(FIT_MAGIC.len()).any(|w| w == FIT_MAGIC);

            if !fit_present {
                let match_type = if matched_str { "string" } else { "MCU magic" };
                findings.push(
                    Finding::new(
                        "microcode_injection",
                        Severity::High,
                        "Microcode reference outside expected firmware region",
                        &format!(
                            "Found microcode {} at offset 0x{:08X} without a preceding FIT \
                             table signature within 4 KB. Legitimate microcode updates are \
                             referenced via the Firmware Interface Table; orphaned references \
                             suggest injection outside the update capsule.",
                            match_type, i
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "match_type": match_type,
                        "fit_signature_found_nearby": false,
                    }))
                    .with_recommendation(
                        "Inspect the firmware image for MCU blobs outside the standard \
                         FIT-referenced update capsule and compare against a known-good baseline.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for MicrocodeInjectionDetector {
    fn name(&self) -> &str {
        "microcode_injection"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_intel_mcu_headers(&data));
        findings.extend(self.check_amd_equiv_table(&data));
        findings.extend(self.check_unexpected_microcode_location(&data));

        Ok(findings)
    }
}
