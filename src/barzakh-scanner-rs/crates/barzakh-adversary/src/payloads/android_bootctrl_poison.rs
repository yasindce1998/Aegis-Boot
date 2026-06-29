use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidBootctrlPoisonPayload;

impl Payload for AndroidBootctrlPoisonPayload {
    fn name(&self) -> &str {
        "android_bootctrl_poison"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // Boot control magic "BCHL"
        data[0] = 0x42; // B
        data[1] = 0x43; // C
        data[2] = 0x48; // H
        data[3] = 0x4C; // L

        // Version (offset 4)
        data[4] = 0x01;

        // Slot A metadata (offset 8):
        // [0] priority, [1] suffix, [2] bootable, [3] retry_count
        data[8] = 0x0F; // priority = 15 (highest)
        data[9] = 0x00; // suffix = 'a'
        data[10] = 0x00; // bootable = 0 (UNBOOTABLE!)
        data[11] = 0x00; // retry_count = 0

        // Slot B metadata (offset 16):
        data[16] = 0x0E; // priority = 14
        data[17] = 0x01; // suffix = 'b'
        data[18] = 0x00; // bootable = 0 (UNBOOTABLE!)
        data[19] = 0x00; // retry_count = 0

        // Merge status (offset 32): invalid value > 3
        data[32] = 0xFF; // invalid merge status

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_bootctrl".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
