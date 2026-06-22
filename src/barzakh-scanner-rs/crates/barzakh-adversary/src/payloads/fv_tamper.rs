use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct FirmwareVolumeTamperPayload;

impl Payload for FirmwareVolumeTamperPayload {
    fn name(&self) -> &str {
        "fv_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        // FV header structure:
        //   offset 0..16:  ZeroVector (16 bytes)
        //   offset 16..32: FileSystemGuid (16 bytes)
        //   offset 32..40: FvLength (8 bytes)
        //   offset 40..44: Signature "_FVH" <-- scanner looks for this
        //   offset 44..48: Attributes (4 bytes)
        //   offset 48..50: HeaderLength (2 bytes)
        //   offset 50..52: Checksum (2 bytes)
        //   offset 52..55: ExtHeaderOffset + Reserved (3 bytes)
        //   offset 55:     Revision (1 byte)
        //   offset 56+:    BlockMap entries

        let fv_offset = 0x1000;
        let header_length: u16 = 56;
        let size = config.size.max(fv_offset + 0x2000);
        let fv_length: u64 = (size - fv_offset) as u64;
        let mut data = vec![0u8; size];

        // ZeroVector (offset 0..16) — all zeros
        // FileSystemGuid (offset 16..32) — EFI_FIRMWARE_FILE_SYSTEM2_GUID
        let fs_guid: [u8; 16] = [
            0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F, 0x99, 0x35, 0x89, 0x61, 0x85, 0xC3,
            0x2D, 0xD3,
        ];
        data[fv_offset + 16..fv_offset + 32].copy_from_slice(&fs_guid);

        // FvLength (offset 32..40)
        let mut cursor = std::io::Cursor::new(&mut data[fv_offset + 32..fv_offset + 40]);
        cursor.write_u64::<LittleEndian>(fv_length)?;

        // _FVH signature (offset 40..44)
        data[fv_offset + 40] = b'_';
        data[fv_offset + 41] = b'F';
        data[fv_offset + 42] = b'V';
        data[fv_offset + 43] = b'H';

        // Attributes (offset 44..48)
        let mut cursor = std::io::Cursor::new(&mut data[fv_offset + 44..fv_offset + 48]);
        cursor.write_u32::<LittleEndian>(0x0004_FEFF)?;

        // HeaderLength (offset 48..50)
        let mut cursor = std::io::Cursor::new(&mut data[fv_offset + 48..fv_offset + 50]);
        cursor.write_u16::<LittleEndian>(header_length)?;

        // Checksum (offset 50..52) — deliberately WRONG (non-zero sum)
        // We need the 16-bit sum of all header words to be NON-zero.
        // Easiest: set checksum field to 0, compute what it should be, then offset it.
        data[fv_offset + 50] = 0x00;
        data[fv_offset + 51] = 0x00;

        // Compute correct checksum
        let mut sum: u16 = 0;
        for chunk in data[fv_offset..fv_offset + header_length as usize].chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                chunk[0] as u16
            };
            sum = sum.wrapping_add(word);
        }
        // Correct checksum would be (0u16.wrapping_sub(sum))
        // We write something else to make the total non-zero
        let wrong_checksum = 0u16.wrapping_sub(sum).wrapping_add(0x1337);
        data[fv_offset + 50] = (wrong_checksum & 0xFF) as u8;
        data[fv_offset + 51] = (wrong_checksum >> 8) as u8;

        // Revision (offset 55)
        data[fv_offset + 55] = 0x02;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "firmware_volume".to_string(),
            min_severity: Severity::High,
        }]
    }
}
