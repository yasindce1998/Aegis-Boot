use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AuthVarRollbackPayload;

impl Payload for AuthVarRollbackPayload {
    fn name(&self) -> &str {
        "auth_var_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // EFI_IMAGE_SECURITY_DATABASE_GUID {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
        let db_guid: [u8; 16] = [
            0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67,
            0x65, 0x6F,
        ];
        let offset = 0x000;
        data[offset..offset + 16].copy_from_slice(&db_guid);

        // Variable name "db" in UTF-16LE
        let name_offset = offset + 16;
        data[name_offset] = b'd';
        data[name_offset + 1] = 0x00;
        data[name_offset + 2] = b'b';
        data[name_offset + 3] = 0x00;

        // Attributes: NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
        // Missing TIME_BASED_AUTHENTICATED_WRITE_ACCESS (0x20) and APPEND_WRITE (0x04)
        let attr_offset = offset + 24;
        let attrs: u32 = 0x01 | 0x02 | 0x04; // NV + BS + RT only, no auth
        data[attr_offset..attr_offset + 4].copy_from_slice(&attrs.to_le_bytes());

        // Timestamp — all zeros (invalid: indicates no authentication)
        // Bytes at offset 32..48 are already zero

        // Data size
        let data_size_offset = offset + 48;
        data[data_size_offset..data_size_offset + 4].copy_from_slice(&0x100u32.to_le_bytes());

        // Second variable: PK with APPEND_WRITE but no TIME_BASED auth
        let pk_offset = 0x200;
        // EFI_GLOBAL_VARIABLE_GUID {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
        let global_guid: [u8; 16] = [
            0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03,
            0x2B, 0x8C,
        ];
        data[pk_offset..pk_offset + 16].copy_from_slice(&global_guid);

        // Variable name "PK" in UTF-16LE
        data[pk_offset + 16] = b'P';
        data[pk_offset + 17] = 0x00;
        data[pk_offset + 18] = b'K';
        data[pk_offset + 19] = 0x00;

        // Attributes: NV | BS | RT | APPEND_WRITE (no TIME_BASED_AUTH)
        let pk_attrs: u32 = 0x01 | 0x02 | 0x04 | 0x08; // APPEND without auth
        data[pk_offset + 24..pk_offset + 28].copy_from_slice(&pk_attrs.to_le_bytes());

        // Monotonic counter at 0 (rollback indicator)
        // Bytes at pk_offset + 32..36 already zero

        // Third variable: KEK with counter at 0
        let kek_offset = 0x400;
        data[kek_offset..kek_offset + 16].copy_from_slice(&global_guid);
        // Variable name "KEK" in UTF-16LE
        let kek_name = b"K\x00E\x00K\x00";
        data[kek_offset + 16..kek_offset + 22].copy_from_slice(kek_name);
        // Attributes: correct (NV | BS | RT | TIME_BASED_AUTH)
        let kek_attrs: u32 = 0x01 | 0x02 | 0x04 | 0x20;
        data[kek_offset + 24..kek_offset + 28].copy_from_slice(&kek_attrs.to_le_bytes());
        // Timestamp is zeroed (all bytes remain 0) — indicates rollback
        // Monotonic counter = 0
        data[kek_offset + 48..kek_offset + 52].copy_from_slice(&0u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "auth_variable".to_string(),
            min_severity: Severity::High,
        }]
    }
}
