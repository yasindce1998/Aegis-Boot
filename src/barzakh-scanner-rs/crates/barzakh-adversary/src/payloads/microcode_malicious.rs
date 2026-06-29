use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct MicrocodeMaliciousPayload;

impl Payload for MicrocodeMaliciousPayload {
    fn name(&self) -> &str {
        "microcode_malicious"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // Place a malicious Intel MCU header at a 48-byte aligned offset.
        // The detector scans at 48-byte boundaries for header_version == 1 (magic 0x01000000 LE).
        let mcu_offset = 48 * 4; // 192, 48-byte aligned

        // header_version = 1 (Intel MCU magic)
        data[mcu_offset] = 0x01;
        data[mcu_offset + 1] = 0x00;
        data[mcu_offset + 2] = 0x00;
        data[mcu_offset + 3] = 0x00;

        // update_revision (offset +4)
        data[mcu_offset + 4] = 0x42;

        // date (offset +8): invalid BCD date 0xFF001301 — high nibble > 9 triggers bad_date
        data[mcu_offset + 8] = 0x01;
        data[mcu_offset + 9] = 0x13;
        data[mcu_offset + 10] = 0x00;
        data[mcu_offset + 11] = 0xFF;

        // processor_signature (offset +12)
        data[mcu_offset + 12] = 0x63;
        data[mcu_offset + 13] = 0x06;
        data[mcu_offset + 14] = 0x05;
        data[mcu_offset + 15] = 0x00;

        // checksum (offset +16)
        data[mcu_offset + 16] = 0xDE;
        data[mcu_offset + 17] = 0xAD;

        // loader_revision (offset +20)
        data[mcu_offset + 20] = 0x01;

        // processor_flags (offset +24)
        data[mcu_offset + 24] = 0x11;

        // data_size (offset +28): 0x10000 = 64KB, exceeding 16KB threshold -> Critical
        data[mcu_offset + 28] = 0x00;
        data[mcu_offset + 29] = 0x00;
        data[mcu_offset + 30] = 0x01;
        data[mcu_offset + 31] = 0x00;

        // total_size (offset +32): deliberately mismatched
        data[mcu_offset + 32] = 0x00;
        data[mcu_offset + 33] = 0x80;
        data[mcu_offset + 34] = 0x01;
        data[mcu_offset + 35] = 0x00;

        // Place a second MCU header with oversized data at another aligned offset
        let mcu_offset2 = 48 * 20;
        if mcu_offset2 + 48 < size {
            data[mcu_offset2] = 0x01;
            data[mcu_offset2 + 1] = 0x00;
            data[mcu_offset2 + 2] = 0x00;
            data[mcu_offset2 + 3] = 0x00;
            // Valid BCD date
            data[mcu_offset2 + 8] = 0x15;
            data[mcu_offset2 + 9] = 0x03;
            data[mcu_offset2 + 10] = 0x20;
            data[mcu_offset2 + 11] = 0x22;
            // data_size = 0x8000 (oversized)
            data[mcu_offset2 + 28] = 0x00;
            data[mcu_offset2 + 29] = 0x80;
            data[mcu_offset2 + 30] = 0x00;
            data[mcu_offset2 + 31] = 0x00;
            // total_size
            data[mcu_offset2 + 32] = 0x30;
            data[mcu_offset2 + 33] = 0x80;
            data[mcu_offset2 + 34] = 0x00;
            data[mcu_offset2 + 35] = 0x00;
        }

        // Place "microcode" string without preceding _FIT signature (triggers
        // check_unexpected_microcode_location)
        let str_offset = 0x5000;
        if str_offset + 9 < size {
            data[str_offset..str_offset + 9].copy_from_slice(b"microcode");
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "microcode_injection".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
