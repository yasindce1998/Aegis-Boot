use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct CsmeUpdateTamperPayload;

impl Payload for CsmeUpdateTamperPayload {
    fn name(&self) -> &str {
        "csme_update_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // First $CPD at offset 0x000 with version=2
        let cpd_magic: [u8; 4] = [0x24, 0x43, 0x50, 0x44];
        data[0x00..0x04].copy_from_slice(&cpd_magic);
        // num_entries = 600 (excessive — triggers detector)
        data[0x04..0x08].copy_from_slice(&600u32.to_le_bytes());
        // header version = 2
        data[0x08] = 0x02;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "csme_update".to_string(),
            min_severity: Severity::High,
        }]
    }
}
