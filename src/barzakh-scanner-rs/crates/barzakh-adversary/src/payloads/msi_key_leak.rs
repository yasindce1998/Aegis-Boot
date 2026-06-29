use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MsiKeyLeakPayload;

impl Payload for MsiKeyLeakPayload {
    fn name(&self) -> &str {
        "msi_key_leak"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x10000);
        let mut data = vec![0u8; size];

        // Intel Boot Guard Key Manifest (KM) structure
        let km_offset = 0x0;
        // Boot Guard KM magic
        let km_magic: [u8; 8] = [0x5F, 0x5F, 0x4B, 0x45, 0x59, 0x4D, 0x5F, 0x5F]; // __KEYM__
        data[km_offset..km_offset + 8].copy_from_slice(&km_magic);

        // KM version (Boot Guard profile 5)
        data[km_offset + 8] = 0x02;
        data[km_offset + 9] = 0x01;

        // KM SVN (Security Version Number)
        data[km_offset + 12] = 0x00;

        // Boot Policy Manifest (BPM) structure
        let bpm_offset = 0x1000;
        let bpm_magic: [u8; 8] = [0x5F, 0x5F, 0x41, 0x43, 0x42, 0x50, 0x5F, 0x5F]; // __ACBP__
        data[bpm_offset..bpm_offset + 8].copy_from_slice(&bpm_magic);

        // MSI's leaked OEM private key fingerprint (SHA-256 of the leaked key modulus)
        // This simulates firmware signed with the key leaked in the 2023 MSI breach
        let key_hash_offset = 0x2000;
        let leaked_key_marker = b"MSI-OEM-KEY-2023";
        data[key_hash_offset..key_hash_offset + leaked_key_marker.len()]
            .copy_from_slice(leaked_key_marker);

        // RSA-2048 signature block (with known weak modulus from leaked key)
        let sig_offset = 0x3000;
        // RSA signature marker
        data[sig_offset] = 0x00;
        data[sig_offset + 1] = 0x01; // PKCS#1 v1.5 padding start
        // Fill padding with 0xFF
        for i in 2..0x100 {
            data[sig_offset + i] = 0xFF;
        }
        data[sig_offset + 0xFF] = 0x00; // padding terminator

        // OEM key modulus (first 32 bytes of leaked MSI key modulus - recognizable pattern)
        let modulus_offset = 0x4000;
        let known_modulus_prefix: [u8; 32] = [
            0xD4, 0x07, 0xE5, 0x13, 0x9B, 0x7A, 0x2C, 0x61,
            0xA8, 0x33, 0x02, 0xF9, 0x44, 0xBE, 0x55, 0xD7,
            0x8E, 0x6F, 0x21, 0xC3, 0x77, 0xAA, 0x09, 0xE8,
            0x50, 0x1B, 0x4D, 0x96, 0xCB, 0x63, 0xF2, 0x38,
        ];
        data[modulus_offset..modulus_offset + 32].copy_from_slice(&known_modulus_prefix);

        // MSI board identifier in firmware volume
        let board_offset = 0x5000;
        let msi_board = b"MS-7D78"; // MSI MEG Z790 ACE
        data[board_offset..board_offset + msi_board.len()].copy_from_slice(msi_board);

        // Intel ACM (Authenticated Code Module) header pointing to the compromised key
        let acm_offset = 0x6000;
        let acm_header_type: u16 = 0x0002; // ACM type
        data[acm_offset..acm_offset + 2].copy_from_slice(&acm_header_type.to_le_bytes());
        let acm_vendor: u32 = 0x8086; // Intel
        data[acm_offset + 4..acm_offset + 8].copy_from_slice(&acm_vendor.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "msi_key_reuse".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
