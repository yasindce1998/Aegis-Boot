use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AsusNvramRedirectPayload;

impl Payload for AsusNvramRedirectPayload {
    fn name(&self) -> &str {
        "asus_nvram_redirect"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x6000);
        let mut data = vec![0u8; size];

        // ASUS EZ Flash NVRAM variable GUID
        // {A5E23B72-3B5A-4C4E-8C2B-4F89DEFA1234} - ASUS update control variable space
        let asus_var_guid: [u8; 16] = [
            0x72, 0x3B, 0xE2, 0xA5, 0x5A, 0x3B, 0x4E, 0x4C,
            0x8C, 0x2B, 0x4F, 0x89, 0xDE, 0xFA, 0x12, 0x34,
        ];
        data[0..16].copy_from_slice(&asus_var_guid);

        // NVRAM variable store header (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
        let nvram_offset = 0x100;
        let var_attrs: u32 = 0x00000007; // NV + BS + RT
        data[nvram_offset..nvram_offset + 4].copy_from_slice(&var_attrs.to_le_bytes());

        // EZ Flash update URL variable name (Unicode UTF-16LE)
        let var_name_offset = 0x110;
        let var_name = "EzFlashUpdateUrl";
        for (i, c) in var_name.encode_utf16().enumerate() {
            data[var_name_offset + i * 2..var_name_offset + i * 2 + 2]
                .copy_from_slice(&c.to_le_bytes());
        }

        // Tampered URL value pointing to attacker-controlled server
        let value_offset = 0x200;
        let malicious_url = b"http://evil-fw-server.net/asus/bios.cap";
        data[value_offset..value_offset + malicious_url.len()].copy_from_slice(malicious_url);

        // ASUS capsule signature verification bypass variable
        let bypass_offset = 0x400;
        let bypass_var = "EzFlashSkipVerify";
        for (i, c) in bypass_var.encode_utf16().enumerate() {
            data[bypass_offset + i * 2..bypass_offset + i * 2 + 2]
                .copy_from_slice(&c.to_le_bytes());
        }
        // Value = 1 (skip signature check)
        data[bypass_offset + 0x40] = 0x01;

        // ASUS-specific capsule header magic
        let capsule_offset = 0x600;
        let asus_magic = b"ASUS";
        data[capsule_offset..capsule_offset + asus_magic.len()].copy_from_slice(asus_magic);

        // Board ID for targeting specific ASUS motherboard models
        let board_offset = 0x700;
        let board_id = b"ROG-STRIX-Z790";
        data[board_offset..board_offset + board_id.len()].copy_from_slice(board_id);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "asus_nvram".to_string(),
            min_severity: Severity::High,
        }]
    }
}
