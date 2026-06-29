use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidGkiTamperPayload;

impl Payload for AndroidGkiTamperPayload {
    fn name(&self) -> &str {
        "android_gki_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // Android boot image header v4 magic "ANDROID!"
        let magic = b"ANDROID!";
        data[0..8].copy_from_slice(magic);

        // Header version = 4
        let mut cursor = std::io::Cursor::new(&mut data[40..44]);
        cursor.write_u32::<LittleEndian>(4)?;

        // Kernel size (non-zero to indicate content present)
        let mut cursor = std::io::Cursor::new(&mut data[8..12]);
        cursor.write_u32::<LittleEndian>(0x0080_0000)?;

        // Ramdisk size
        let mut cursor = std::io::Cursor::new(&mut data[16..20]);
        cursor.write_u32::<LittleEndian>(0x0010_0000)?;

        // AVB footer magic "AVB0" at offset 0x2000
        let avb_offset = 0x2000;
        data[avb_offset] = b'A';
        data[avb_offset + 1] = b'V';
        data[avb_offset + 2] = b'B';
        data[avb_offset + 3] = b'0';

        // AVB version
        let mut cursor = std::io::Cursor::new(&mut data[avb_offset + 4..avb_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x0001_0002)?;

        // Hash descriptor with zeroed hash (signature removed)
        // 32-byte SHA-256 hash at avb_offset + 0x40 is all zeros (already zero)

        // vendor_boot magic "VNDRBOOT" at offset 0x3000
        let vb_offset = 0x3000;
        let vb_magic = b"VNDRBOOT";
        data[vb_offset..vb_offset + vb_magic.len()].copy_from_slice(vb_magic);

        // Oversized vendor ramdisk (> 64MB, suspicious)
        let mut cursor = std::io::Cursor::new(&mut data[vb_offset + 8..vb_offset + 12]);
        cursor.write_u32::<LittleEndian>(0x0800_0000)?;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_gki_boot".to_string(),
            min_severity: Severity::High,
        }]
    }
}
