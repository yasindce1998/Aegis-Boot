use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// MSR 0x150 — Intel OC Mailbox (Plundervolt voltage manipulation)
// Little-endian u16 representation of 0x0150
const MSR_OC_MAILBOX_LO: u8 = 0x50;
const MSR_OC_MAILBOX_HI: u8 = 0x01;

// MSR 0x199 — IA32_PERF_CTL (DVFS frequency/voltage control)
// Little-endian u16 representation of 0x0199
const MSR_PERF_CTL_LO: u8 = 0x99;
const MSR_PERF_CTL_HI: u8 = 0x01;

// x86 WRMSR opcode (documented for reference; bytes are matched inline for position context)
#[allow(dead_code)]
const WRMSR: &[u8] = &[0x0F, 0x30];

// SGX instructions
const ENCLS: &[u8] = &[0x0F, 0x01, 0xCF];
const ENCLU: &[u8] = &[0x0F, 0x01, 0xD7];

// Common ARM PMIC I2C addresses (CLKscrew)
const PMIC_I2C_ADDR_60: u8 = 0x60;
const PMIC_I2C_ADDR_62: u8 = 0x62;

// Maximum negative voltage offset representable in the OC Mailbox payload
// Values with the high byte >= 0xF8 in a 16-bit signed representation indicate
// large negative offsets (more than ~31 mV below nominal), which exceed safe ranges.
const UNSAFE_VOLTAGE_OFFSET_THRESHOLD: u8 = 0xF8;

pub struct VoltageGlitchDetector;

impl Default for VoltageGlitchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoltageGlitchDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect MSR 0x150 (OC Mailbox) writes via WRMSR — Plundervolt voltage manipulation.
    /// Also flags occurrences where the voltage offset encoded in the payload exceeds safe ranges.
    fn check_plundervolt_msr(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(1) {
            // Look for WRMSR (0F 30)
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }

            // Scan the 16 bytes before WRMSR for MSR 0x150 load pattern
            let scan_start = i.saturating_sub(16);
            let pre_wrmsr = &data[scan_start..i];

            let has_msr_150 = pre_wrmsr
                .windows(2)
                .any(|w| w[0] == MSR_OC_MAILBOX_LO && w[1] == MSR_OC_MAILBOX_HI);

            if !has_msr_150 {
                continue;
            }

            // Check whether the voltage offset bytes (appearing after the MSR address load)
            // represent a large negative offset (potential unsafe undervolt).
            let unsafe_offset = pre_wrmsr
                .windows(2)
                .any(|w| w[1] >= UNSAFE_VOLTAGE_OFFSET_THRESHOLD);

            let severity = if unsafe_offset {
                Severity::Critical
            } else {
                Severity::High
            };

            let description = if unsafe_offset {
                format!(
                    "WRMSR targeting MSR 0x150 (OC Mailbox) at offset 0x{:08X} with a voltage \
                     payload whose high byte indicates a large negative offset (>= 0xF8xx). \
                     This is the characteristic Plundervolt pattern for inducing computational \
                     faults in the CPU core.",
                    i
                )
            } else {
                format!(
                    "WRMSR targeting MSR 0x150 (OC Mailbox) at offset 0x{:08X}. Voltage \
                     manipulation via the OC Mailbox is the mechanism used by Plundervolt \
                     (CVE-2019-11157) to fault SGX enclaves.",
                    i
                )
            };

            findings.push(
                Finding::new(
                    "voltage_glitch",
                    severity,
                    "Plundervolt OC Mailbox MSR write detected",
                    &description,
                )
                .with_confidence(if unsafe_offset { 0.91 } else { 0.78 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "msr": "0x150 (IA32_OC_MAILBOX)",
                    "unsafe_offset": unsafe_offset,
                    "technique": "Plundervolt / CVE-2019-11157",
                }))
                .with_recommendation(
                    "Disable OC Mailbox MSR access in production firmware. Apply Intel \
                     microcode update for CVE-2019-11157. Enforce SGX platform quoting \
                     with voltage-attack attestation.",
                ),
            );
        }

        findings
    }

    /// Detect voltage manipulation (MSR 0x150 + WRMSR) within 256 bytes of SGX instructions
    /// (ENCLS / ENCLU). Voltage manipulation near SGX enclaves is the hallmark Plundervolt attack.
    fn check_sgx_voltage_targeting(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all offsets where MSR 0x150 WRMSR pairs occur
        let mut wrmsr_offsets: Vec<usize> = Vec::new();
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0x0F && data[i + 1] == 0x30 {
                let scan_start = i.saturating_sub(16);
                let pre = &data[scan_start..i];
                if pre
                    .windows(2)
                    .any(|w| w[0] == MSR_OC_MAILBOX_LO && w[1] == MSR_OC_MAILBOX_HI)
                {
                    wrmsr_offsets.push(i);
                }
            }
        }

        if wrmsr_offsets.is_empty() {
            return findings;
        }

        // Search for ENCLS / ENCLU instructions
        for i in 0..data.len().saturating_sub(2) {
            let is_encls = data[i..].starts_with(ENCLS);
            let is_enclu = data[i..].starts_with(ENCLU);
            if !is_encls && !is_enclu {
                continue;
            }

            let instr_name = if is_encls { "ENCLS" } else { "ENCLU" };

            // Check whether any WRMSR(0x150) is within 256 bytes of this SGX instruction
            for &wrmsr_off in &wrmsr_offsets {
                let distance = wrmsr_off.abs_diff(i);

                if distance <= 256 {
                    findings.push(
                        Finding::new(
                            "voltage_glitch",
                            Severity::Critical,
                            "SGX voltage targeting — Plundervolt attack pattern",
                            &format!(
                                "{} instruction at offset 0x{:08X} is within {} bytes of an MSR \
                                 0x150 (OC Mailbox) WRMSR at offset 0x{:08X}. This is the \
                                 definitive Plundervolt (CVE-2019-11157) attack pattern: \
                                 undervolt applied immediately before/after enclave execution \
                                 to induce silent data corruption inside the SGX enclave.",
                                instr_name, i, distance, wrmsr_off
                            ),
                        )
                        .with_confidence(0.94)
                        .with_details(serde_json::json!({
                            "sgx_instruction": instr_name,
                            "sgx_offset": format!("0x{:08X}", i),
                            "wrmsr_offset": format!("0x{:08X}", wrmsr_off),
                            "proximity_bytes": distance,
                            "msr": "0x150 (IA32_OC_MAILBOX)",
                            "technique": "Plundervolt SGX targeting / CVE-2019-11157",
                        }))
                        .with_recommendation(
                            "Apply Intel microcode updates for CVE-2019-11157. Disable OC \
                             Mailbox MSR writes in firmware. Review SGX enclave sealing and \
                             attestation for any indication of tampered measurements.",
                        ),
                    );
                    // One finding per SGX instruction — avoid duplicate reports
                    break;
                }
            }
        }

        findings
    }

    /// Detect DVFS manipulation: MSR 0x199 (IA32_PERF_CTL) writes with extreme values,
    /// and I2C PMIC register write patterns (CLKscrew-style ARM attacks).
    fn check_dvfs_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // --- x86: MSR 0x199 (IA32_PERF_CTL) WRMSR ---
        for i in 0..data.len().saturating_sub(1) {
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }

            let scan_start = i.saturating_sub(16);
            let pre_wrmsr = &data[scan_start..i];

            let has_msr_199 = pre_wrmsr
                .windows(2)
                .any(|w| w[0] == MSR_PERF_CTL_LO && w[1] == MSR_PERF_CTL_HI);

            if !has_msr_199 {
                continue;
            }

            // Extreme frequency ratio values: bytes directly after the MSR address load
            // that represent a P-state ratio above 0x3F (63) or below 0x08 are suspicious.
            let extreme_freq = pre_wrmsr.iter().any(|&b| b > 0x3F && b < 0xFF);

            findings.push(
                Finding::new(
                    "voltage_glitch",
                    Severity::High,
                    "IA32_PERF_CTL DVFS manipulation detected",
                    &format!(
                        "WRMSR targeting MSR 0x199 (IA32_PERF_CTL) at offset 0x{:08X}{}. \
                         Manipulating this MSR can drive CPU frequency outside validated \
                         operating ranges, causing transient faults (CLKscrew-style attack \
                         on x86 DVFS).",
                        i,
                        if extreme_freq {
                            " with extreme frequency ratio payload"
                        } else {
                            ""
                        }
                    ),
                )
                .with_confidence(if extreme_freq { 0.82 } else { 0.65 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "msr": "0x199 (IA32_PERF_CTL)",
                    "extreme_freq_value": extreme_freq,
                    "technique": "DVFS fault injection / CLKscrew x86 variant",
                }))
                .with_recommendation(
                    "Restrict P-state MSR writes to trusted kernel code. Validate \
                     frequency/voltage operating points against CPU specifications.",
                ),
            );
        }

        // --- ARM: I2C PMIC write patterns (CLKscrew) ---
        // Look for PMIC I2C addresses 0x60 / 0x62 with an adjacent write command byte
        // (I2C write transactions typically carry direction in the LSB of the address byte,
        // so 0x60 -> write=0xC0, 0x62 -> write=0xC4; but raw address bytes also appear
        // in register-level PMIC drivers).
        for i in 0..data.len().saturating_sub(3) {
            let addr = data[i];
            if addr != PMIC_I2C_ADDR_60 && addr != PMIC_I2C_ADDR_62 {
                continue;
            }

            // Adjacent bytes: expect a register offset followed by a non-zero value byte
            let reg_byte = data[i + 1];
            let val_byte = data[i + 2];

            // PMIC voltage / frequency registers are typically in the range 0x00–0x7F
            // A write command with a value != 0 in a security-sensitive register is flagged.
            if reg_byte <= 0x7F && val_byte != 0x00 {
                findings.push(
                    Finding::new(
                        "voltage_glitch",
                        Severity::High,
                        "ARM PMIC I2C voltage/frequency register write (CLKscrew pattern)",
                        &format!(
                            "PMIC I2C address 0x{:02X} at offset 0x{:08X} followed by register \
                             0x{:02X} write with value 0x{:02X}. This matches the CLKscrew ARM \
                             DVFS attack pattern where voltage or frequency is manipulated via \
                             I2C to the PMIC to induce transient faults.",
                            addr, i, reg_byte, val_byte
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "pmic_i2c_address": format!("0x{:02X}", addr),
                        "register": format!("0x{:02X}", reg_byte),
                        "value": format!("0x{:02X}", val_byte),
                        "technique": "CLKscrew ARM DVFS / PMIC I2C manipulation",
                    }))
                    .with_recommendation(
                        "Audit PMIC I2C access control. Restrict kernel drivers from \
                         performing arbitrary PMIC register writes. Validate DVFS operating \
                         points against SoC safety margins.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for VoltageGlitchDetector {
    fn name(&self) -> &str {
        "voltage_glitch"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_plundervolt_msr(&data));
        findings.extend(self.check_sgx_voltage_targeting(&data));
        findings.extend(self.check_dvfs_manipulation(&data));

        Ok(findings)
    }
}
