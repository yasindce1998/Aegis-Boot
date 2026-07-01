use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosPplBypassPayload;

impl Payload for IosPplBypassPayload {
    fn name(&self) -> &str {
        "ios_ppl_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x100);
        let mut data = vec![0u8; size];

        // APRR magic with zeroed config (PPL disabled)
        let aprr_magic: [u8; 4] = [0x41, 0x50, 0x52, 0x52]; // "APRR"
        data[0..4].copy_from_slice(&aprr_magic);

        // config_flags = 0 (disabled)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        // All-permissive PTE mask
        data[8..12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_ppl".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
