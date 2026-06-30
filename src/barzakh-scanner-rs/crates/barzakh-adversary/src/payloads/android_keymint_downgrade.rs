use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an Android KeyMint key-attestation record that has been downgraded: the
/// security level is SOFTWARE (no TEE/StrongBox protection) and the attested
/// verified-boot state is Unverified. This models a forged/emulated KeyMint TA
/// used to pass attestation on a compromised device.
pub struct AndroidKeymintDowngradePayload;

impl Payload for AndroidKeymintDowngradePayload {
    fn name(&self) -> &str {
        "android_keymint_downgrade"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let blob = b"android.security.keymint attestation record\n\
                     securityLevel: Software\n\
                     verifiedBootState: Unverified\n";

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_keymint".to_string(),
            min_severity: Severity::High,
        }]
    }
}
