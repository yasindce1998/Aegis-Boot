use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SignaturePlantPayload;

impl Payload for SignaturePlantPayload {
    fn name(&self) -> &str {
        "signature_plant"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Plant known bootkit signatures at various offsets
        // These are the exact patterns from barzakh-core's memory detector

        // "BlackLotus" at offset 0x100
        let sig1 = b"BlackLotus";
        data[0x100..0x100 + sig1.len()].copy_from_slice(sig1);

        // "CosmicStrand" at offset 0x400
        let sig2 = b"CosmicStrand";
        data[0x400..0x400 + sig2.len()].copy_from_slice(sig2);

        // Infinite loop jmp $ (\xEB\xFE) at offset 0x800
        data[0x800] = 0xEB;
        data[0x801] = 0xFE;

        // Custom bootkit marker \x48\xB8UEFI_BK! at offset 0xC00
        let marker = b"\x48\xB8UEFI_BK!";
        data[0xC00..0xC00 + marker.len()].copy_from_slice(marker);

        // "MoonBounce" at offset 0x1000
        let sig3 = b"MoonBounce";
        data[0x1000..0x1000 + sig3.len()].copy_from_slice(sig3);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "memory".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
