use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ThermalRaplExfilPayload;

impl Payload for ThermalRaplExfilPayload {
    fn name(&self) -> &str {
        "thermal_rapl_exfil"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate dense RAPL MSR writes that trigger check_rapl_msr_manipulation.
        // The detector looks for WRMSR (0F 30) preceded within 16 bytes by MSR address
        // patterns: 0x610 -> [0x10, 0x06], 0x619 -> [0x19, 0x06], 0x614 -> [0x14, 0x06].
        // Threshold: >2 RAPL WRMSRs within 256 bytes.

        let base = 0x200;

        // First RAPL WRMSR: MOV ECX, 0x610 then WRMSR
        // MOV ECX, imm32: B9 10 06 00 00
        data[base] = 0xB9;
        data[base + 1] = 0x10; // MSR_PKG_POWER_LIMIT low byte
        data[base + 2] = 0x06; // MSR_PKG_POWER_LIMIT high byte
        data[base + 3] = 0x00;
        data[base + 4] = 0x00;
        // XOR EAX, EAX; MOV EAX, power_limit_value
        data[base + 5] = 0x31;
        data[base + 6] = 0xC0;
        data[base + 7] = 0xB8;
        data[base + 8] = 0xFF;
        data[base + 9] = 0x7F;
        data[base + 10] = 0x00;
        data[base + 11] = 0x00;
        // WRMSR
        data[base + 12] = 0x0F;
        data[base + 13] = 0x30;

        // Second RAPL WRMSR: MSR 0x619 (DRAM_POWER_LIMIT)
        let off2 = base + 40;
        data[off2] = 0xB9;
        data[off2 + 1] = 0x19; // MSR_DRAM_POWER_LIMIT low
        data[off2 + 2] = 0x06; // MSR_DRAM_POWER_LIMIT high
        data[off2 + 3] = 0x00;
        data[off2 + 4] = 0x00;
        data[off2 + 5] = 0xB8;
        data[off2 + 6] = 0x00;
        data[off2 + 7] = 0x80;
        data[off2 + 8] = 0x00;
        data[off2 + 9] = 0x00;
        // WRMSR
        data[off2 + 10] = 0x0F;
        data[off2 + 11] = 0x30;

        // Third RAPL WRMSR: MSR 0x614 (PKG_ENERGY_STATUS)
        let off3 = base + 80;
        data[off3] = 0xB9;
        data[off3 + 1] = 0x14; // MSR_PKG_ENERGY_STATUS low
        data[off3 + 2] = 0x06; // MSR_PKG_ENERGY_STATUS high
        data[off3 + 3] = 0x00;
        data[off3 + 4] = 0x00;
        data[off3 + 5] = 0x31;
        data[off3 + 6] = 0xC0;
        // WRMSR
        data[off3 + 7] = 0x0F;
        data[off3 + 8] = 0x30;

        // Fourth RAPL WRMSR for density (back to 0x610)
        let off4 = base + 120;
        data[off4] = 0xB9;
        data[off4 + 1] = 0x10;
        data[off4 + 2] = 0x06;
        data[off4 + 3] = 0x00;
        data[off4 + 4] = 0x00;
        data[off4 + 5] = 0x0F;
        data[off4 + 6] = 0x30;

        // Also place ACPI thermal zone strings near a TEMPERATURE_TARGET WRMSR
        // to trigger check_thermal_target_manipulation
        let temp_base = 0x1000;
        // MOV ECX, 0x1A2 (TEMPERATURE_TARGET)
        data[temp_base] = 0xB9;
        data[temp_base + 1] = 0xA2; // MSR_TEMPERATURE_TARGET low
        data[temp_base + 2] = 0x01; // MSR_TEMPERATURE_TARGET high
        data[temp_base + 3] = 0x00;
        data[temp_base + 4] = 0x00;
        data[temp_base + 5] = 0x0F;
        data[temp_base + 6] = 0x30; // WRMSR
                                    // Place "_TMP" string nearby
        data[temp_base + 20] = b'_';
        data[temp_base + 21] = b'T';
        data[temp_base + 22] = b'M';
        data[temp_base + 23] = b'P';

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "thermal_covert".to_string(),
            min_severity: Severity::High,
        }]
    }
}
