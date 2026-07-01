use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosSepForgePayload;

impl Payload for IosSepForgePayload {
    fn name(&self) -> &str {
        "ios_sep_forge"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // SEPI magic (SEP firmware image)
        let sepi_magic: [u8; 4] = [0x73, 0x65, 0x70, 0x69]; // "sepi"
        data[0..4].copy_from_slice(&sepi_magic);

        // Version
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // Size
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        // Flags: debug enabled (bit 0)
        data[12..16].copy_from_slice(&0x01u32.to_le_bytes());

        // Signature at +0x10: zeroed (unsigned)
        // Already zeros

        // Also add a SEPOS section with forged attestation
        let sepos_offset = 0x120;
        data[sepos_offset..sepos_offset + 5].copy_from_slice(b"SEPOS");
        // Key attestation at +0x10 from SEPOS: repeated 0xAA (forged)
        let att_offset = sepos_offset + 0x10;
        data[att_offset..att_offset + 64].fill(0xAA);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_secure_enclave".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
