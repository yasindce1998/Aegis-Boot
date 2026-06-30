use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a Windows boot-configuration blob (UTF-16LE strings, as found in a BCD
/// store) that identifies the Windows Boot Manager and enables the
/// code-integrity-disabling options `nointegritychecks` and `testsigning` —
/// the configuration a bootkit sets so it can load an unsigned kernel driver.
pub struct WindowsBcdTamperPayload;

impl WindowsBcdTamperPayload {
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
}

impl Payload for WindowsBcdTamperPayload {
    fn name(&self) -> &str {
        "windows_bcd_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        let mut rec: Vec<u8> = Vec::new();
        for s in ["Windows Boot Manager", "nointegritychecks", "testsigning"] {
            rec.extend_from_slice(&Self::utf16le(s));
            rec.extend_from_slice(&[0x00, 0x00]); // UTF-16 NUL separator
        }

        let at = 0x100;
        let end = (at + rec.len()).min(size);
        data[at..end].copy_from_slice(&rec[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "windows_bootchain".to_string(),
            min_severity: Severity::High,
        }]
    }
}
