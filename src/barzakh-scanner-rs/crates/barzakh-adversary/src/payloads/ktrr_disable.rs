use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an Apple-Silicon boot-state blob in which the KTRR / CTRR (AMCC)
/// kernel-text lockdown is left un-locked (CTRR_LOCK=0). With the Read-only
/// Region writable, Kernel Patch Protection is defeated and kernel text can be
/// patched — the precondition for a persistent iOS/macOS kernel implant.
pub struct KtrrDisablePayload;

impl Payload for KtrrDisablePayload {
    fn name(&self) -> &str {
        "ktrr_disable"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let blob = b"AMCC KTRR configuration\n\
                     RoRgnBasAddr=0x800000000\n\
                     RoRgnEndAddr=0x808000000\n\
                     CTRR_LOCK=0\n\
                     ctrr_lock: 0 (region writable)\n";

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_ktrr".to_string(),
            min_severity: Severity::High,
        }]
    }
}
