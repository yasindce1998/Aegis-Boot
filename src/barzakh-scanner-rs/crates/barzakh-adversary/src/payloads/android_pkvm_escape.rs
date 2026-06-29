use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidPkvmEscapePayload;

impl Payload for AndroidPkvmEscapePayload {
    fn name(&self) -> &str {
        "android_pkvm_escape"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // pvmfw header magic "pvmf" at offset 0x0
        data[0] = b'p';
        data[1] = b'v';
        data[2] = b'm';
        data[3] = b'f';

        // pvmfw version (v2 = Android 15+)
        let mut cursor = std::io::Cursor::new(&mut data[4..8]);
        cursor.write_u32::<LittleEndian>(0x0002)?;

        // Image size
        let mut cursor = std::io::Cursor::new(&mut data[8..12]);
        cursor.write_u32::<LittleEndian>(size as u32)?;

        // Forged signature — zeroed to bypass verification
        // Signature offset at 0x40, 256 bytes zeroed (already zero in vec)

        // pKVM hypervisor EL2 vector table modification at offset 0x800
        // "PKVM" marker
        let el2_offset = 0x800;
        data[el2_offset] = b'P';
        data[el2_offset + 1] = b'K';
        data[el2_offset + 2] = b'V';
        data[el2_offset + 3] = b'M';

        // EL2 exception vector — branch to shellcode (B #0x1000)
        // ARM64 unconditional branch: 0x14000400 (branch forward 0x1000 bytes)
        let mut cursor = std::io::Cursor::new(&mut data[el2_offset + 4..el2_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x1400_0400)?;

        // AVF instance.img debug policy injection at offset 0x1000
        let avf_offset = 0x1000;
        data[avf_offset] = b'A';
        data[avf_offset + 1] = b'V';
        data[avf_offset + 2] = b'F';
        data[avf_offset + 3] = b'i';

        // Debug policy: enable all debug (0xFF = all flags set)
        data[avf_offset + 8] = 0xFF;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_pkvm".to_string(),
            min_severity: Severity::High,
        }]
    }
}
