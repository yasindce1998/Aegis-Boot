use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PspVersionRollbackPayload;

impl Payload for PspVersionRollbackPayload {
    fn name(&self) -> &str {
        "psp_version_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // First PSP L2 directory "$PL2" at offset 0x000 with SVN=8
        let psp_l2_magic: [u8; 4] = [0x24, 0x50, 0x4C, 0x32];
        data[0x00..0x04].copy_from_slice(&psp_l2_magic);
        data[0x0C..0x10].copy_from_slice(&8u32.to_le_bytes());

        // Second PSP L2 directory at offset 0x1000 with SVN=2 (rollback)
        data[0x1000..0x1004].copy_from_slice(&psp_l2_magic);
        data[0x100C..0x1010].copy_from_slice(&2u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "psp_version_chain".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
