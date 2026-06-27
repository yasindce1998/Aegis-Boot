use anyhow::Result;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ArmIbootPayload;

impl Payload for ArmIbootPayload {
    fn name(&self) -> &str {
        "arm_iboot"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // IMG4 container header (Apple's signed image format)
        // DER sequence tag + length
        let offset = 0x100;
        data[offset] = 0x30; // SEQUENCE tag
        data[offset + 1] = 0x82; // long-form length (2 bytes follow)
        data[offset + 2] = 0x10; // length high byte
        data[offset + 3] = 0x00; // length low byte

        // IMG4 magic OID: 1.2.840.113635.100.4 ("IMG4")
        let img4_magic = b"IMG4";
        data[offset + 4..offset + 8].copy_from_slice(img4_magic);

        // IM4P (payload) tag at offset 0x200
        let im4p_offset = 0x200;
        data[im4p_offset..im4p_offset + 4].copy_from_slice(b"IM4P");

        // Component tag — "ibot" (iBoot) indicating boot-chain payload
        data[im4p_offset + 4..im4p_offset + 8].copy_from_slice(b"ibot");

        // Modified KBAG (Key Bag) — indicates the encryption envelope was tampered with
        // A valid KBAG wraps the AES-GCM key for the payload; modifying it is a
        // jailbreak/exploit indicator
        let kbag_offset = 0x400;
        data[kbag_offset..kbag_offset + 4].copy_from_slice(b"KBAG");
        // KBAG type 1 = production key (type 0 = development)
        let mut cursor = std::io::Cursor::new(&mut data[kbag_offset + 4..kbag_offset + 8]);
        cursor.write_u32::<BigEndian>(0x0000_0001)?;
        // IV: all zeros indicates a bypass/null encryption (exploit indicator)
        // (16 bytes of 0x00 already from vec initialization)
        // Key: pattern that suggests key material was extracted
        let key_offset = kbag_offset + 24;
        for i in 0..32 {
            data[key_offset + i] = 0xAA;
        }

        // SHSH (signature) blob with zeroed hash — indicates signature check bypass
        let shsh_offset = 0x600;
        data[shsh_offset..shsh_offset + 4].copy_from_slice(b"SHSH");
        // Certificate length = 0 (no valid signing certificate)
        let mut cursor = std::io::Cursor::new(&mut data[shsh_offset + 4..shsh_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x0000_0000)?;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "arm_trustzone".to_string(),
            min_severity: Severity::High,
        }]
    }
}
