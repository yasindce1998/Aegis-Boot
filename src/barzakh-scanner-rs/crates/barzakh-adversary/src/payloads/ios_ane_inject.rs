use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosAneInjectPayload;

impl Payload for IosAneInjectPayload {
    fn name(&self) -> &str {
        "ios_ane_inject"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // ANE firmware magic "ane0"
        let ane_magic: [u8; 4] = [0x61, 0x6E, 0x65, 0x30];
        data[0..4].copy_from_slice(&ane_magic);

        // Version
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // Size: normal (1MB)
        data[8..12].copy_from_slice(&0x100000u32.to_le_bytes());
        // Flags: development flag set (bit 1)
        data[12..16].copy_from_slice(&0x02u32.to_le_bytes());

        // Signature at +0x10: zeroed (unsigned)
        // Already zeros

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_ane_boot".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
