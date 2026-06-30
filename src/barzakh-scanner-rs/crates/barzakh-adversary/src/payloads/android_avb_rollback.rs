use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an Android Verified Boot `vbmeta` image (libavb, big-endian) whose
/// flags disable both signature verification and the dm-verity hashtree, with
/// the rollback index reset to 0. This is the configuration an attacker leaves
/// behind to boot a tampered/downgraded system image past Verified Boot.
pub struct AndroidAvbRollbackPayload;

impl Payload for AndroidAvbRollbackPayload {
    fn name(&self) -> &str {
        "android_avb_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        let at = 0x100;
        // AvbVBMetaImageHeader: magic + (zeroed version/size fields) + rollback
        // index (offset 112, u64 BE) + flags (offset 120, u32 BE).
        data[at..at + 4].copy_from_slice(b"AVB0");
        // required_libavb_version_major = 1.
        data[at + 4..at + 8].copy_from_slice(&1u32.to_be_bytes());
        // rollback_index = 0 (anti-rollback stripped).
        data[at + 112..at + 120].copy_from_slice(&0u64.to_be_bytes());
        // flags = HASHTREE_DISABLED | VERIFICATION_DISABLED.
        data[at + 120..at + 124].copy_from_slice(&0x3u32.to_be_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_avb".to_string(),
            min_severity: Severity::High,
        }]
    }
}
