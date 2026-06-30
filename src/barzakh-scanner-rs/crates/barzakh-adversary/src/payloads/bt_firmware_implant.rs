use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a Broadcom/Cypress Bluetooth controller firmware patch (.hcd /
/// patchram) that injects a code blob into controller RAM via a Write_RAM
/// (0xFC4C) HCI command and then jumps to it with Launch_RAM (0xFC4E) — a
/// persistent radio-side BT controller implant.
pub struct BtFirmwareImplantPayload;

impl Payload for BtFirmwareImplantPayload {
    fn name(&self) -> &str {
        "bt_firmware_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(b"BCM4378 patchram .hcd\n");
        // Write_RAM: opcode (LE), param_len, address (LE), code blob.
        blob.extend_from_slice(&[0x4C, 0xFC]);
        blob.push(0x44); // 68 bytes of params (4 addr + 64 code)
        blob.extend_from_slice(&0x0020_0000u32.to_le_bytes());
        blob.extend_from_slice(&[0xCCu8; 64]);
        // Launch_RAM: opcode, param_len, address.
        blob.extend_from_slice(&[0x4E, 0xFC]);
        blob.push(0x04);
        blob.extend_from_slice(&0x0020_0000u32.to_le_bytes());

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "bluetooth_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
