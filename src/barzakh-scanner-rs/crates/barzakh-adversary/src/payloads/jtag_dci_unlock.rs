use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct JtagDciUnlockPayload;

impl Payload for JtagDciUnlockPayload {
    fn name(&self) -> &str {
        "jtag_dci_unlock"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Trigger check_dci_enable: WRMSR (0F 30) preceded by MSR 0xC80 address bytes.
        // MSR 0xC80 = IA32_DEBUG_INTERFACE, LE bytes: [0x80, 0x0C].
        let base = 0x200;

        // MOV ECX, 0xC80: B9 80 0C 00 00
        data[base] = 0xB9;
        data[base + 1] = 0x80; // MSR 0xC80 low
        data[base + 2] = 0x0C; // MSR 0xC80 high
        data[base + 3] = 0x00;
        data[base + 4] = 0x00;

        // MOV EAX, 1 (enable bit 0 set): B8 01 00 00 00
        data[base + 5] = 0xB8;
        data[base + 6] = 0x01; // bit 0 = enable DCI
        data[base + 7] = 0x00;
        data[base + 8] = 0x00;
        data[base + 9] = 0x00;

        // XOR EDX, EDX: 31 D2
        data[base + 10] = 0x31;
        data[base + 11] = 0xD2;

        // WRMSR: 0F 30
        data[base + 12] = 0x0F;
        data[base + 13] = 0x30;

        // Trigger check_jtag_tap_enable: GPIO pin mux sequence [0x0C, 0x01, 0x02, 0x03, 0x04]
        let gpio_offset = 0x400;
        data[gpio_offset] = 0x0C;
        data[gpio_offset + 1] = 0x01; // TCK
        data[gpio_offset + 2] = 0x02; // TMS
        data[gpio_offset + 3] = 0x03; // TDI
        data[gpio_offset + 4] = 0x04; // TDO

        // Also place ASCII markers "JTAG" and "DCI_EN" (triggers string marker detection)
        let jtag_str_offset = 0x600;
        data[jtag_str_offset..jtag_str_offset + 4].copy_from_slice(b"JTAG");

        let dci_str_offset = 0x700;
        data[dci_str_offset..dci_str_offset + 6].copy_from_slice(b"DCI_EN");

        // Trigger check_debug_consent_bypass: MSR 0xDB0 (HDC) + "BootGuard" within 256 bytes
        let hdc_base = 0xA00;
        // MOV ECX, 0xDB0: B9 B0 0D 00 00
        data[hdc_base] = 0xB9;
        data[hdc_base + 1] = 0xB0; // MSR 0xDB0 low
        data[hdc_base + 2] = 0x0D; // MSR 0xDB0 high
        data[hdc_base + 3] = 0x00;
        data[hdc_base + 4] = 0x00;
        // WRMSR
        data[hdc_base + 5] = 0x0F;
        data[hdc_base + 6] = 0x30;
        // "BootGuard" within 256 bytes
        let bg_offset = hdc_base + 64;
        data[bg_offset..bg_offset + 9].copy_from_slice(b"BootGuard");

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "debug_interface".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
