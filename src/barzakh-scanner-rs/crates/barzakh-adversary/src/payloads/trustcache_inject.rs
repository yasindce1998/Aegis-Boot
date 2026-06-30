use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a loadable iOS Image4 Trust Cache ("ltrs") whose single entry is
/// flagged ad-hoc, authorizing an attacker-controlled cdhash. Dynamically
/// loading such a trust cache lets unsigned binaries run under AMFI — the
/// foundation of iOS jailbreaks and post-exploitation implants.
pub struct TrustcacheInjectPayload;

impl Payload for TrustcacheInjectPayload {
    fn name(&self) -> &str {
        "trustcache_inject"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let mut tc: Vec<u8> = Vec::new();
        tc.extend_from_slice(b"Image4 Trust Cache\n");
        tc.extend_from_slice(b"ltrs"); // loadable trust cache magic
        tc.extend_from_slice(&1u32.to_le_bytes()); // version
        tc.extend_from_slice(&1u32.to_le_bytes()); // entry_count
        tc.extend_from_slice(&[0xDE; 20]); // forged cdhash
        tc.push(0x02); // hash_type (SHA-256, truncated)
        tc.push(0x01); // flags: ad-hoc

        let at = 0x40;
        let end = (at + tc.len()).min(size);
        data[at..end].copy_from_slice(&tc[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_trustcache".to_string(),
            min_severity: Severity::High,
        }]
    }
}
