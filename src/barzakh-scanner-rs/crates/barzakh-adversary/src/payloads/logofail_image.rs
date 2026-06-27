use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct LogofailImagePayload;

impl Payload for LogofailImagePayload {
    fn name(&self) -> &str {
        "logofail_image"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // Write EFI Firmware Volume header to establish context
        let fv_offset = 0x00;
        // Zero vector (16 bytes)
        // FileSystemGuid (16 bytes) — EFI_FIRMWARE_FILE_SYSTEM2_GUID
        let fs_guid: [u8; 16] = [
            0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F, 0x99, 0x35, 0x89, 0x61, 0x85, 0xC3,
            0x2D, 0xD3,
        ];
        data[fv_offset + 16..fv_offset + 32].copy_from_slice(&fs_guid);
        // FvLength
        let fv_length = size as u64;
        data[fv_offset + 32..fv_offset + 40].copy_from_slice(&fv_length.to_le_bytes());
        // Signature "_FVH"
        data[fv_offset + 40..fv_offset + 44].copy_from_slice(b"_FVH");
        // Attributes
        data[fv_offset + 44..fv_offset + 48].copy_from_slice(&0x0004FEFFu32.to_le_bytes());
        // HeaderLength
        data[fv_offset + 48..fv_offset + 50].copy_from_slice(&0x0048u16.to_le_bytes());

        // Embed malicious BMP at offset 0x200 with oversized biSizeImage
        let bmp_offset = 0x200;
        // BMP Magic "BM"
        data[bmp_offset] = 0x42;
        data[bmp_offset + 1] = 0x4D;
        // File size — declare much larger than available space
        let fake_file_size: u32 = 0x00FFFFFF;
        data[bmp_offset + 2..bmp_offset + 6].copy_from_slice(&fake_file_size.to_le_bytes());
        // Reserved (4 bytes)
        // Pixel data offset
        data[bmp_offset + 10..bmp_offset + 14].copy_from_slice(&54u32.to_le_bytes());
        // DIB Header size (BITMAPINFOHEADER = 40)
        data[bmp_offset + 14..bmp_offset + 18].copy_from_slice(&40u32.to_le_bytes());
        // Width = 4096
        data[bmp_offset + 18..bmp_offset + 22].copy_from_slice(&4096i32.to_le_bytes());
        // Height = INT_MIN (integer overflow trigger)
        data[bmp_offset + 22..bmp_offset + 26].copy_from_slice(&i32::MIN.to_le_bytes());
        // Planes = 1
        data[bmp_offset + 26..bmp_offset + 28].copy_from_slice(&1u16.to_le_bytes());
        // Bits per pixel = 24
        data[bmp_offset + 28..bmp_offset + 30].copy_from_slice(&24u16.to_le_bytes());
        // Compression = 0 (BI_RGB)
        // biSizeImage — exceeds remaining firmware data
        let overflow_size: u32 = 0x00F00000;
        data[bmp_offset + 34..bmp_offset + 38].copy_from_slice(&overflow_size.to_le_bytes());

        // Second BMP at offset 0x400 with dimensions exceeding 10000
        let bmp2_offset = 0x400;
        data[bmp2_offset] = 0x42;
        data[bmp2_offset + 1] = 0x4D;
        data[bmp2_offset + 2..bmp2_offset + 6].copy_from_slice(&0x00100000u32.to_le_bytes());
        data[bmp2_offset + 10..bmp2_offset + 14].copy_from_slice(&54u32.to_le_bytes());
        data[bmp2_offset + 14..bmp2_offset + 18].copy_from_slice(&40u32.to_le_bytes());
        // Width = 20000 (suspiciously large)
        data[bmp2_offset + 18..bmp2_offset + 22].copy_from_slice(&20000i32.to_le_bytes());
        // Height = 20000
        data[bmp2_offset + 22..bmp2_offset + 26].copy_from_slice(&20000i32.to_le_bytes());
        data[bmp2_offset + 26..bmp2_offset + 28].copy_from_slice(&1u16.to_le_bytes());
        data[bmp2_offset + 28..bmp2_offset + 30].copy_from_slice(&32u16.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "logofail".to_string(),
            min_severity: Severity::High,
        }]
    }
}
