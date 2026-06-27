use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BlacklotusMokPayload;

impl Payload for BlacklotusMokPayload {
    fn name(&self) -> &str {
        "blacklotus_mok"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Simulate MokList variable with shim GUID and revoked hash
        let offset = 0x000;

        // Shim GUID {605b1cb4-f877-4504-9e5e-cd99301e4d97} — little-endian
        let shim_guid: [u8; 16] = [
            0xC1, 0xC4, 0x1B, 0x60, 0x77, 0xF8, 0x04, 0x45, 0x9E, 0x5E, 0xCD, 0x99, 0x30, 0x1E,
            0x4D, 0x97,
        ];
        data[offset..offset + 16].copy_from_slice(&shim_guid);

        // MokList variable name (UTF-16LE): "MokList"
        let moklist_offset = offset + 32;
        let moklist_name = b"M\x00o\x00k\x00L\x00i\x00s\x00t\x00";
        data[moklist_offset..moklist_offset + moklist_name.len()].copy_from_slice(moklist_name);

        // Inject known-revoked BlackLotus hash prefix after the GUID
        let hash_offset = offset + 64;
        // Known revoked hash prefix: 0x80B4D96B
        data[hash_offset] = 0x80;
        data[hash_offset + 1] = 0xB4;
        data[hash_offset + 2] = 0xD9;
        data[hash_offset + 3] = 0x6B;
        // Fill remainder with fake SHA-256 hash data
        for i in 4..32 {
            data[hash_offset + i] = (i * 7 + 0x42) as u8;
        }

        // Add BcdStore with Baton Drop integrity disable flag
        let bcd_offset = 0x400;
        data[bcd_offset..bcd_offset + 8].copy_from_slice(b"BcdStore");
        // Write the CVE-2022-21894 integrity disable flag
        let flag_offset = bcd_offset + 32;
        data[flag_offset..flag_offset + 4].copy_from_slice(&0x10000007u32.to_le_bytes());

        // Multiple shimx64.efi references (persistence indicator)
        let paths: [&[u8]; 4] = [
            b"\\EFI\\Microsoft\\Boot\\shimx64.efi",
            b"\\EFI\\Boot\\shimx64.efi",
            b"\\EFI\\ubuntu\\shimx64.efi",
            b"\\EFI\\hidden\\shimx64.efi",
        ];
        let mut path_offset = 0x800;
        for path in &paths {
            let end = (path_offset + path.len()).min(size);
            let copy_len = end - path_offset;
            data[path_offset..path_offset + copy_len].copy_from_slice(&path[..copy_len]);
            path_offset += 0x100;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "blacklotus".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
