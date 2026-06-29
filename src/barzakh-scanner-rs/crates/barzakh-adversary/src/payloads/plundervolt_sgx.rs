use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PlundervoltSgxPayload;

impl Payload for PlundervoltSgxPayload {
    fn name(&self) -> &str {
        "plundervolt_sgx"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate Plundervolt attack pattern:
        // WRMSR (0F 30) preceded by MSR 0x150 address bytes (OC_MAILBOX),
        // with voltage offset high byte >= 0xF8 (Critical severity),
        // within 256 bytes of ENCLS (0F 01 CF) targeting SGX.

        let base = 0x400;

        // MOV ECX, 0x150 (MSR OC_MAILBOX): B9 50 01 00 00
        data[base] = 0xB9;
        data[base + 1] = 0x50; // MSR 0x150 low byte
        data[base + 2] = 0x01; // MSR 0x150 high byte
        data[base + 3] = 0x00;
        data[base + 4] = 0x00;

        // MOV EAX, undervolt_value (high byte >= 0xF8 for critical detection)
        data[base + 5] = 0xB8;
        data[base + 6] = 0x00;
        data[base + 7] = 0x00;
        data[base + 8] = 0xF8; // voltage offset high byte — triggers Critical severity
        data[base + 9] = 0xFF;

        // XOR EDX, EDX
        data[base + 10] = 0x31;
        data[base + 11] = 0xD2;

        // WRMSR: 0F 30
        data[base + 12] = 0x0F;
        data[base + 13] = 0x30;

        // Place ENCLS (0F 01 CF) within 256 bytes to trigger check_sgx_voltage_targeting
        let encls_offset = base + 100;
        data[encls_offset] = 0x0F;
        data[encls_offset + 1] = 0x01;
        data[encls_offset + 2] = 0xCF; // ENCLS

        // Place a second MSR 0x150 WRMSR + ENCLU combination
        let base2 = 0x800;
        data[base2] = 0xB9;
        data[base2 + 1] = 0x50;
        data[base2 + 2] = 0x01;
        data[base2 + 3] = 0x00;
        data[base2 + 4] = 0x00;
        // Normal voltage offset (still triggers but lower severity)
        data[base2 + 5] = 0xB8;
        data[base2 + 6] = 0x00;
        data[base2 + 7] = 0x10;
        data[base2 + 8] = 0xE0;
        data[base2 + 9] = 0xFF;
        data[base2 + 10] = 0x0F;
        data[base2 + 11] = 0x30; // WRMSR

        // ENCLU (0F 01 D7) nearby
        let enclu_offset = base2 + 80;
        data[enclu_offset] = 0x0F;
        data[enclu_offset + 1] = 0x01;
        data[enclu_offset + 2] = 0xD7; // ENCLU

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "voltage_glitch".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
