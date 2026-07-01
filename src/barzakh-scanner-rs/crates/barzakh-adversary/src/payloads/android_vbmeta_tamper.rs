use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidVbmetaTamperPayload;

impl Payload for AndroidVbmetaTamperPayload {
    fn name(&self) -> &str {
        "android_vbmeta_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // AVB magic "AVB0"
        let avb_magic: [u8; 4] = [0x41, 0x56, 0x42, 0x30];
        data[0..4].copy_from_slice(&avb_magic);

        // Algorithm type = 0 (AVB_ALGORITHM_TYPE_NONE — verification disabled)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        // Rollback index = 0 (anti-rollback defeated)
        data[16..24].copy_from_slice(&0u64.to_le_bytes());

        // Hash descriptor area zeroed (already zeros) — no partition hashes bound

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_vbmeta_chain".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
