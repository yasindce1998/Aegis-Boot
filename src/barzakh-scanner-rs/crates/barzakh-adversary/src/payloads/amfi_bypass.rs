use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an iOS NVRAM/boot-args blob that disables Apple Mobile File Integrity
/// and kernel code-signing enforcement (amfi_get_out_of_my_way=1,
/// cs_enforcement_disable=1). This is the boot policy that lets a jailbroken
/// device execute unsigned binaries.
pub struct AmfiBypassPayload;

impl Payload for AmfiBypassPayload {
    fn name(&self) -> &str {
        "amfi_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let blob = b"nvram boot-args=amfi_get_out_of_my_way=1 cs_enforcement_disable=1 \
                     -amfi_allow_any_signature serial=3\n\
                     AppleMobileFileIntegrity: enforcement disabled\n";

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_amfi".to_string(),
            min_severity: Severity::High,
        }]
    }
}
