use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SmuFirmwareTamperPayload;

impl Payload for SmuFirmwareTamperPayload {
    fn name(&self) -> &str {
        "smu_firmware_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x400);
        let mut data = vec![0u8; size];

        // SMU magic: \x01\x00\x00\x00 + "SMU"
        data[0] = 0x01;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x53; // 'S'
        data[5] = 0x4D; // 'M'
        data[6] = 0x55; // 'U'

        // Declared size at +8: 128KB (valid range)
        data[8..12].copy_from_slice(&0x20000u32.to_le_bytes());

        // Signature region at +0x100: all zeros (unsigned — attack pattern)
        // Already zeros in our vec

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "smu_firmware".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
