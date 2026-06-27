use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct CapsuleTamperPayload;

impl Payload for CapsuleTamperPayload {
    fn name(&self) -> &str {
        "capsule_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // EFI_CAPSULE_GUID {3B6686BD-0D76-4030-B70E-B5519E2FC5A0}
        let capsule_guid: [u8; 16] = [
            0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40, 0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F,
            0xC5, 0xA0,
        ];
        let offset = 0x000;
        data[offset..offset + 16].copy_from_slice(&capsule_guid);

        // HeaderSize — valid (28 bytes minimum)
        let header_size: u32 = 28;
        data[offset + 16..offset + 20].copy_from_slice(&header_size.to_le_bytes());

        // Flags: PERSIST_ACROSS_RESET (0x10000) without POPULATE_SYSTEM_TABLE
        // This is suspicious: PERSIST without POPULATE
        let flags: u32 = 0x00010000;
        data[offset + 20..offset + 24].copy_from_slice(&flags.to_le_bytes());

        // CapsuleImageSize — exceeds actual available data
        let fake_capsule_size: u32 = 0x00800000; // 8MB but file is only ~8KB
        data[offset + 24..offset + 28].copy_from_slice(&fake_capsule_size.to_le_bytes());

        // Second capsule with FMP GUID and invalid item count
        let fmp_offset = 0x800;
        // EFI_FMP_CAPSULE_GUID {6DCBD5ED-E82D-4C44-BDA1-7194199AD92A}
        let fmp_guid: [u8; 16] = [
            0xED, 0xD5, 0xCB, 0x6D, 0x2D, 0xE8, 0x44, 0x4C, 0xBD, 0xA1, 0x71, 0x94, 0x19, 0x9A,
            0xD9, 0x2A,
        ];
        data[fmp_offset..fmp_offset + 16].copy_from_slice(&fmp_guid);

        // HeaderSize for FMP capsule
        let fmp_header_size: u32 = 28;
        data[fmp_offset + 16..fmp_offset + 20].copy_from_slice(&fmp_header_size.to_le_bytes());

        // Flags: POPULATE_SYSTEM_TABLE (0x20000) | PERSIST (0x10000)
        let fmp_flags: u32 = 0x00030000;
        data[fmp_offset + 20..fmp_offset + 24].copy_from_slice(&fmp_flags.to_le_bytes());

        // CapsuleImageSize — slightly larger than actual but not absurd
        let fmp_capsule_size: u32 = 0x600;
        data[fmp_offset + 24..fmp_offset + 28].copy_from_slice(&fmp_capsule_size.to_le_bytes());

        // FMP Capsule Header (after EFI Capsule Header)
        let fmp_payload_offset = fmp_offset + 28;
        // Version = 1
        data[fmp_payload_offset..fmp_payload_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        // EmbeddedDriverCount = 0
        data[fmp_payload_offset + 4..fmp_payload_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        // PayloadItemCount = 1000 (absurdly high — exceeds available space)
        data[fmp_payload_offset + 8..fmp_payload_offset + 12]
            .copy_from_slice(&1000u32.to_le_bytes());

        // Third capsule: HeaderSize < 28 (invalid minimum)
        let bad_offset = 0x1000;
        data[bad_offset..bad_offset + 16].copy_from_slice(&capsule_guid);
        // HeaderSize = 16 (less than 28 minimum)
        data[bad_offset + 16..bad_offset + 20].copy_from_slice(&16u32.to_le_bytes());
        data[bad_offset + 20..bad_offset + 24].copy_from_slice(&0x00030000u32.to_le_bytes());
        data[bad_offset + 24..bad_offset + 28].copy_from_slice(&0x100u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "capsule_update".to_string(),
            min_severity: Severity::High,
        }]
    }
}
