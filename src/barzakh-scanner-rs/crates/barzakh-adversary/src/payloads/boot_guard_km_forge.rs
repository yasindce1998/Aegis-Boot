use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BootGuardKmForgePayload;

impl Payload for BootGuardKmForgePayload {
    fn name(&self) -> &str {
        "boot_guard_km_forge"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Key Manifest "__KEYM__" at offset 0x000
        let keym: [u8; 8] = [0x5F, 0x5F, 0x4B, 0x45, 0x59, 0x4D, 0x5F, 0x5F];
        data[0x00..0x08].copy_from_slice(&keym);

        // Key hash at offset +0x14 (256 bytes) — all zeros = forged/empty key
        // Already zeros in our vec — this is the attack pattern

        // Boot Policy Manifest "__ACBP__" at offset 0x1000
        let bpm: [u8; 8] = [0x5F, 0x5F, 0x41, 0x43, 0x42, 0x50, 0x5F, 0x5F];
        data[0x1000..0x1008].copy_from_slice(&bpm);

        // BPM enforcement flags at offset +0x10 = 0 (enforcement disabled)
        data[0x1010..0x1014].copy_from_slice(&0u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "boot_guard_km".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
