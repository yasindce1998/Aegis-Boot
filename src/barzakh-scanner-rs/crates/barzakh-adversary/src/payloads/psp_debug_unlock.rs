use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PspDebugUnlockPayload;

impl Payload for PspDebugUnlockPayload {
    fn name(&self) -> &str {
        "psp_debug_unlock"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Debug Unlock token "DBUK" at offset 0x100
        let dbuk_magic: [u8; 4] = [0x44, 0x42, 0x55, 0x4B];
        data[0x100..0x104].copy_from_slice(&dbuk_magic);

        // Token payload (fake unlock credentials)
        data[0x104..0x108].copy_from_slice(&0x00000001u32.to_le_bytes()); // unlock flag
        data[0x108..0x10C].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // nonce

        // Also place a PSP directory with debug policy entry
        let psp_dir: [u8; 4] = [0x24, 0x50, 0x53, 0x50];
        data[0x1000..0x1004].copy_from_slice(&psp_dir);
        // num_entries = 2
        data[0x1008..0x100C].copy_from_slice(&2u32.to_le_bytes());

        // Entry 0: normal type
        data[0x1010] = 0x01;
        data[0x1018..0x101C].copy_from_slice(&0x100u32.to_le_bytes()); // size

        // Entry 1: type 0x09 (debug policy)
        let entry1 = 0x1020;
        data[entry1] = 0x09;
        data[entry1 + 8..entry1 + 12].copy_from_slice(&0x200u32.to_le_bytes()); // size > 0

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "psp_secure_debug".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
