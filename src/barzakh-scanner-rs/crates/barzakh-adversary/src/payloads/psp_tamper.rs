use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PspTamperPayload;

impl Payload for PspTamperPayload {
    fn name(&self) -> &str {
        "psp_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // AMD PSP Directory Header "$PSP"
        let offset = 0x000;
        data[offset] = 0x24; // '$'
        data[offset + 1] = 0x50; // 'P'
        data[offset + 2] = 0x53; // 'S'
        data[offset + 3] = 0x50; // 'P'

        // Checksum = 0 (zeroed — bypasses validation)
        data[offset + 4..offset + 8].copy_from_slice(&0u32.to_le_bytes());

        // Total entries = 8 (reasonable count)
        data[offset + 8..offset + 12].copy_from_slice(&8u32.to_le_bytes());

        // Entry 0: PSP-OS (type 0x0C) with oversized entry
        let entry_base = offset + 16;
        data[entry_base] = 0x0C; // Type: PSP OS
        data[entry_base + 1] = 0x00;
        data[entry_base + 2] = 0x00;
        data[entry_base + 3] = 0x00;
        // Subprogram + ROM ID
        data[entry_base + 4..entry_base + 8].copy_from_slice(&0u32.to_le_bytes());
        // Size = 0x200000 (2MB — abnormally large for PSP OS)
        data[entry_base + 8..entry_base + 12].copy_from_slice(&0x00200000u32.to_le_bytes());
        // Location
        data[entry_base + 12..entry_base + 16].copy_from_slice(&0x00100000u32.to_le_bytes());

        // Entry 1: SMU firmware (type 0x08) with zero size (wiped)
        let entry1 = entry_base + 16;
        data[entry1] = 0x08; // Type: SMU firmware
        data[entry1 + 8..entry1 + 12].copy_from_slice(&0u32.to_le_bytes()); // Size = 0

        // Entry 2: Normal entry for contrast
        let entry2 = entry_base + 32;
        data[entry2] = 0x01; // Type: PSP FW Boot Loader
        data[entry2 + 8..entry2 + 12].copy_from_slice(&0x00010000u32.to_le_bytes());

        // Second PSP combo directory at offset 0x2000
        let combo_offset = 0x2000;
        // "2PSP" magic
        data[combo_offset] = 0x32;
        data[combo_offset + 1] = 0x50;
        data[combo_offset + 2] = 0x53;
        data[combo_offset + 3] = 0x50;
        // Checksum = 0 (zeroed)
        // Entries = 300 (exceeds reasonable maximum of 256)
        data[combo_offset + 8..combo_offset + 12].copy_from_slice(&300u32.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "amd_psp".to_string(),
            min_severity: Severity::High,
        }]
    }
}
