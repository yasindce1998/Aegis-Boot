use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosPolicyTamperPayload;

impl Payload for IosPolicyTamperPayload {
    fn name(&self) -> &str {
        "ios_policy_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x100);
        let mut data = vec![0u8; size];

        // lpol magic
        let lpol_magic: [u8; 4] = [0x6C, 0x70, 0x6F, 0x6C]; // "lpol"
        data[0..4].copy_from_slice(&lpol_magic);

        // version = 1 (valid)
        data[4..8].copy_from_slice(&1u32.to_le_bytes());

        // nonce_hash at +8: zeroed (anti-replay defeated)
        // Already zeros

        // next_stage_hash at +40: zeroed (chain binding broken)
        // Already zeros

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_local_policy".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
