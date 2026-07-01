use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidVerityDisablePayload;

impl Payload for AndroidVerityDisablePayload {
    fn name(&self) -> &str {
        "android_verity_disable"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // dm-verity magic with disabled flag set
        let dm_verity_magic: u32 = 0xB001B001;
        data[0..4].copy_from_slice(&dm_verity_magic.to_le_bytes());

        // Flags at +4: bit 0 = disabled
        data[4..8].copy_from_slice(&0x01u32.to_le_bytes());

        // Also embed "veritymode=disabled" boot parameter
        let param = b"veritymode=disabled";
        data[0x80..0x80 + param.len()].copy_from_slice(param);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_init_verity".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
