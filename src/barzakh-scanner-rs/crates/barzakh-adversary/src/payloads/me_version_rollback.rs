use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MeVersionRollbackPayload;

impl Payload for MeVersionRollbackPayload {
    fn name(&self) -> &str {
        "me_version_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // First $MN2 manifest at offset 0x000 with SVN=5
        data[0x00] = 0x24; // '$'
        data[0x01] = 0x4D; // 'M'
        data[0x02] = 0x4E; // 'N'
        data[0x03] = 0x32; // '2'
        // SVN at +0x24 = 5
        data[0x24..0x28].copy_from_slice(&5u32.to_le_bytes());

        // Second $MN2 manifest at offset 0x1000 with SVN=1 (rollback)
        let offset2 = 0x1000;
        data[offset2] = 0x24;
        data[offset2 + 1] = 0x4D;
        data[offset2 + 2] = 0x4E;
        data[offset2 + 3] = 0x32;
        // SVN at +0x24 = 1 (lower than first — rollback)
        data[offset2 + 0x24..offset2 + 0x28].copy_from_slice(&1u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "me_version_chain".to_string(),
            min_severity: Severity::High,
        }]
    }
}
