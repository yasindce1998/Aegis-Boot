use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct DxeDepexHijackPayload;

impl Payload for DxeDepexHijackPayload {
    fn name(&self) -> &str {
        "dxe_depex_hijack"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // EFI_SECTION_DXE_DEPEX type marker (0x13)
        let offset = 0x000;
        // Section size (3 bytes LE) + type (1 byte)
        let section_size: u32 = 0x200;
        data[offset] = (section_size & 0xFF) as u8;
        data[offset + 1] = ((section_size >> 8) & 0xFF) as u8;
        data[offset + 2] = ((section_size >> 16) & 0xFF) as u8;
        data[offset + 3] = 0x13; // EFI_SECTION_DXE_DEPEX

        // Build a DEPEX with invalid opcodes and stack imbalance
        let depex_start = offset + 4;
        let mut pos = depex_start;

        // PUSH (0x02) + GUID — valid
        data[pos] = 0x02;
        pos += 1;
        // Random GUID (16 bytes)
        let guid1: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        data[pos..pos + 16].copy_from_slice(&guid1);
        pos += 16;

        // PUSH another GUID
        data[pos] = 0x02;
        pos += 1;
        let guid2: [u8; 16] = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
            0x1F, 0x20,
        ];
        data[pos..pos + 16].copy_from_slice(&guid2);
        pos += 16;

        // AND (0x03) — valid, combines two pushed values
        data[pos] = 0x03;
        pos += 1;

        // Invalid opcode! (0xFE is not a valid DEPEX opcode)
        data[pos] = 0xFE;
        pos += 1;

        // Another invalid opcode (0xAB)
        data[pos] = 0xAB;
        pos += 1;

        // Push 30+ more GUIDs to exceed the 32-GUID threshold
        for i in 0..33 {
            data[pos] = 0x02; // PUSH
            pos += 1;
            for j in 0..16 {
                data[pos + j] = ((i * 16 + j + 0x30) & 0xFF) as u8;
            }
            pos += 16;
        }

        // End without proper stack balance (many items still on stack)
        data[pos] = 0x08; // END opcode
        pos += 1;

        // Second DEPEX section with SOR opcode (suspicious)
        let sec2_offset = 0x800;
        let sec2_size: u32 = 0x100;
        data[sec2_offset] = (sec2_size & 0xFF) as u8;
        data[sec2_offset + 1] = ((sec2_size >> 8) & 0xFF) as u8;
        data[sec2_offset + 2] = ((sec2_size >> 16) & 0xFF) as u8;
        data[sec2_offset + 3] = 0x13;

        let depex2_start = sec2_offset + 4;
        // SOR (Schedule On Request) opcode = 0x09
        data[depex2_start] = 0x09;
        // TRUE (0x06)
        data[depex2_start + 1] = 0x06;
        // END (0x08)
        data[depex2_start + 2] = 0x08;

        let _ = pos; // suppress unused warning

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "dxe_dispatcher".to_string(),
            min_severity: Severity::High,
        }]
    }
}
