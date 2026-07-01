use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosIbootPatchPayload;

impl Payload for IosIbootPatchPayload {
    fn name(&self) -> &str {
        "ios_iboot_patch"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // iBoot magic
        data[0..5].copy_from_slice(b"iBoot");

        // No version string (stripped) — triggers version-missing finding

        // Signature region at +0x40: all zeros (unsigned)
        // Already zeros

        // NOP sled at code entrypoint (ARM64 NOP = 0xD503201F in LE = [1F, 20, 03, D5])
        let nop: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];
        for i in 0..4 {
            let off = 0x40 + i * 4;
            data[off..off + 4].copy_from_slice(&nop);
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_iboot".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
