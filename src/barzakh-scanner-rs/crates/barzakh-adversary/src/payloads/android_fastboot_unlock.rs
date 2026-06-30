use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a fastboot/bootloader state blob describing an unlocked, unlockable
/// device: `get_unlock_ability: 1`, the `unlock_critical` capability, and an
/// 'orange' verified-boot state. This is the bootloader posture that lets an
/// attacker flash unsigned boot/vbmeta/system images and defeat the root of trust.
pub struct AndroidFastbootUnlockPayload;

impl Payload for AndroidFastbootUnlockPayload {
    fn name(&self) -> &str {
        "android_fastboot_unlock"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let blob = b"fastboot getvar:\n\
                     unlock_critical: yes\n\
                     get_unlock_ability: 1\n\
                     DEVICE STATE - unlocked\n\
                     androidboot.verifiedbootstate=orange\n";

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_fastboot".to_string(),
            min_severity: Severity::High,
        }]
    }
}
