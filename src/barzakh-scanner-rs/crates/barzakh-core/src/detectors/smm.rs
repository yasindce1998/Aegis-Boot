use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SMRAM_BASE_TYPICAL: u64 = 0xA0000;
const SMRAM_SIZE_TYPICAL: u64 = 0x10000;
const TSEG_BASE_TYPICAL: u64 = 0x7F000000;

pub struct SmmDetector;

impl Default for SmmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SmmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_smram_lock(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for SMRAM Control register patterns
        // D_LCK bit (bit 4) in SMRAMC register should be set
        let smramc_patterns: &[&[u8]] = &[
            b"SMRAMC",
            &[0x9D, 0x00], // typical SMRAMC register encoding
        ];

        for pattern in smramc_patterns {
            if let Some(pos) = data.windows(pattern.len()).position(|w| w == *pattern) {
                // Check if lock bit is clear (vulnerable)
                if pos + pattern.len() + 1 < data.len() {
                    let reg_value = data[pos + pattern.len()];
                    if reg_value & 0x10 == 0 {
                        findings.push(
                            Finding::new(
                                "smm",
                                Severity::Critical,
                                "SMRAM not locked",
                                "SMRAM lock bit (D_LCK) is not set. This allows \
                                 ring-0 code to access and modify SMM handler code.",
                            )
                            .with_confidence(0.70)
                            .with_details(serde_json::json!({
                                "register_offset": format!("0x{:08X}", pos),
                                "register_value": format!("0x{:02X}", reg_value),
                            }))
                            .with_recommendation(
                                "Ensure SMRAM is locked during platform initialization.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_smm_callout(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for SMI handler dispatchers that reference outside SMRAM
        // Pattern: CALL/JMP to address outside TSEG
        let call_pattern: &[u8] = &[0xFF, 0x15]; // CALL [addr]
        for (i, window) in data.windows(6).enumerate() {
            if window[..2] == *call_pattern {
                let target = u32::from_le_bytes(window[2..6].try_into().unwrap_or([0; 4])) as u64;

                // If target is outside SMRAM/TSEG ranges
                let in_smram =
                    (SMRAM_BASE_TYPICAL..SMRAM_BASE_TYPICAL + SMRAM_SIZE_TYPICAL).contains(&target);
                let in_tseg = target >= TSEG_BASE_TYPICAL;

                if target != 0 && !in_smram && !in_tseg && target < 0x1_0000_0000 {
                    findings.push(
                        Finding::new(
                            "smm",
                            Severity::High,
                            "Potential SMM callout detected",
                            &format!(
                                "Indirect call at offset 0x{:08X} targets 0x{:08X} \
                                 which is outside SMRAM. May indicate SMM callout vulnerability.",
                                i, target
                            ),
                        )
                        .with_confidence(0.50)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "target": format!("0x{:08X}", target),
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for SmmDetector {
    fn name(&self) -> &str {
        "smm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_smram_lock(&data));
        findings.extend(self.check_smm_callout(&data));

        Ok(findings)
    }
}
