use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MeltdownPteLeakPayload;

impl Payload for MeltdownPteLeakPayload {
    fn name(&self) -> &str {
        "meltdown_pte_leak"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate CLFLUSH + RDTSC cache flush-reload pattern.
        // The spectre_gadgets detector check_cache_flush_reload looks for:
        //   CLFLUSH: 0F AE /7 (modrm bits 5:3 = 111, i.e., modrm & 0x38 == 0x38)
        //   followed by RDTSC (0F 31) within 64 bytes.

        // Place multiple flush+reload sequences for a realistic Meltdown/Flush+Reload gadget
        let sequences = [0x200, 0x300, 0x400, 0x500];
        for &base in &sequences {
            if base + 64 >= size {
                break;
            }

            // CLFLUSH [rax]: 0F AE 38 (modrm=0x38 means [eax] with reg=7)
            data[base] = 0x0F;
            data[base + 1] = 0xAE;
            data[base + 2] = 0x38; // ModRM: mod=00, reg=111, rm=000 -> [eax]

            // Some intervening instructions (MOV to access target memory line)
            data[base + 3] = 0x8B; // MOV
            data[base + 4] = 0x00; // [eax]
            data[base + 5] = 0x48; // REX.W
            data[base + 6] = 0x8B; // MOV
            data[base + 7] = 0x04; // SIB
            data[base + 8] = 0xC5; // scale=8, index=eax, base=none
            data[base + 9] = 0x00;
            data[base + 10] = 0x00;
            data[base + 11] = 0x10;
            data[base + 12] = 0x00;

            // RDTSC: 0F 31 (timing probe)
            data[base + 20] = 0x0F;
            data[base + 21] = 0x31;

            // Second CLFLUSH + RDTSC pair closer together
            data[base + 30] = 0x0F;
            data[base + 31] = 0xAE;
            data[base + 32] = 0x39; // ModRM: [ecx] with reg=7 (0x38 | 0x01 mod bits still give reg=7)
                                    // Actually modrm 0x39: mod=00, reg=111, rm=001 -> [ecx] — bits 5:3 = 111

            data[base + 40] = 0x0F;
            data[base + 41] = 0x31;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "spectre_gadgets".to_string(),
            min_severity: Severity::High,
        }]
    }
}
