use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SpectreBtbInjectPayload;

impl Payload for SpectreBtbInjectPayload {
    fn name(&self) -> &str {
        "spectre_btb_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate a cluster of >5 unprotected indirect branch instructions (FF 15 / FF 25)
        // within a 4KB window, without LFENCE (0F AE E8) preceding them.
        // The detector flags when >5 unprotected indirect branches appear in a 4KB window.
        let base = 0x100;
        for i in 0..8 {
            let offset = base + i * 32;
            // CALL [mem] — FF 15 xx xx xx xx
            data[offset] = 0xFF;
            data[offset + 1] = 0x15;
            data[offset + 2] = 0x40;
            data[offset + 3] = 0x10;
            data[offset + 4] = 0x00;
            data[offset + 5] = 0x00;

            // JMP [mem] — FF 25 xx xx xx xx (interleaved for realism)
            let jmp_offset = offset + 16;
            data[jmp_offset] = 0xFF;
            data[jmp_offset + 1] = 0x25;
            data[jmp_offset + 2] = 0x80;
            data[jmp_offset + 3] = 0x20;
            data[jmp_offset + 4] = 0x00;
            data[jmp_offset + 5] = 0x00;
        }

        // Also place a conditional branch + NOP sled (Spectre v1 barrier removal pattern)
        // JA (0x77) + rel8 + 3-byte NOP sled (matches LFENCE length exactly)
        let barrier_offset = 0x1000;
        data[barrier_offset] = 0x77; // JA
        data[barrier_offset + 1] = 0x10; // rel8 offset
        data[barrier_offset + 2] = 0x90; // NOP
        data[barrier_offset + 3] = 0x90; // NOP
        data[barrier_offset + 4] = 0x90; // NOP (3 bytes = LFENCE length)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "spectre_gadgets".to_string(),
            min_severity: Severity::Medium,
        }]
    }
}
