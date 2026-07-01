use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PspTrustletInjectPayload;

impl Payload for PspTrustletInjectPayload {
    fn name(&self) -> &str {
        "psp_trustlet_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // PSP Directory "$PSP" at offset 0x000
        let psp_dir_magic: [u8; 4] = [0x24, 0x50, 0x53, 0x50];
        data[0x00..0x04].copy_from_slice(&psp_dir_magic);
        // num_entries = 3
        data[0x08..0x0C].copy_from_slice(&3u32.to_le_bytes());

        // Entry 0: known type 0x01 (PSP FW Boot Loader)
        let entry0 = 0x10;
        data[entry0] = 0x01;
        data[entry0 + 4..entry0 + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // location
        data[entry0 + 8..entry0 + 12].copy_from_slice(&0x400u32.to_le_bytes()); // size

        // Entry 1: known type 0x0C (PSP OS)
        let entry1 = entry0 + 16;
        data[entry1] = 0x0C;
        data[entry1 + 4..entry1 + 8].copy_from_slice(&0x2000u32.to_le_bytes());
        data[entry1 + 8..entry1 + 12].copy_from_slice(&0x800u32.to_le_bytes());

        // Entry 2: ROGUE type 0xEE (injected trustlet)
        let entry2 = entry1 + 16;
        data[entry2] = 0xEE;
        data[entry2 + 4..entry2 + 8].copy_from_slice(&0x3000u32.to_le_bytes());
        data[entry2 + 8..entry2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());

        // Place fake trustlet at 0x3000 with zeroed signature at +0x100
        // (signature region already zeroed in our vec)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "psp_trustlets".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
