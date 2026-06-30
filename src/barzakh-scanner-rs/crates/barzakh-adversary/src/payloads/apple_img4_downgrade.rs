use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an Apple Image4-style manifest blob whose trust properties have been
/// downgraded: the Certificate Production status (CPRO) and Security mode (CSEC)
/// are both DER-boolean `false`, and the boot nonce (snon) is zeroed. Together
/// these describe a Permissive Security / development boot policy that disables
/// the SEP-enforced secure boot chain on Apple Silicon.
pub struct AppleImg4DowngradePayload;

impl Payload for AppleImg4DowngradePayload {
    fn name(&self) -> &str {
        "apple_img4_downgrade"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        const DER_BOOL_FALSE: [u8; 3] = [0x01, 0x01, 0x00];

        let mut m: Vec<u8> = Vec::new();
        m.extend_from_slice(b"IMG4"); // container magic
        m.extend_from_slice(b"IM4M"); // signed manifest magic
        m.extend_from_slice(b"CPRO"); // production status...
        m.extend_from_slice(&DER_BOOL_FALSE); // ...= false
        m.extend_from_slice(b"CSEC"); // security mode...
        m.extend_from_slice(&DER_BOOL_FALSE); // ...= false
        m.extend_from_slice(b"snon"); // boot nonce...
        m.extend_from_slice(&[0u8; 20]); // ...all zero (replay)

        let at = 0x80;
        let end = (at + m.len()).min(size);
        data[at..end].copy_from_slice(&m[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "apple_img4".to_string(),
            min_severity: Severity::High,
        }]
    }
}
