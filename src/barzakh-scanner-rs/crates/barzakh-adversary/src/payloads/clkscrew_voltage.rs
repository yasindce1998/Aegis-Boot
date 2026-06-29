use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ClkscrewVoltagePayload;

impl Payload for ClkscrewVoltagePayload {
    fn name(&self) -> &str {
        "clkscrew_voltage"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate CLKscrew/DVFS manipulation pattern.
        // The voltage_glitch detector check_dvfs_manipulation looks for:
        //   ARM PMIC I2C address bytes: 0x60 or 0x62 followed by a register byte <= 0x7F
        //   and a non-zero value byte (PMIC voltage regulator write via I2C bus).

        // Place multiple PMIC I2C voltage regulator writes
        let pmic_sequences = [
            (0x200, 0x60u8, 0x10u8, 0xA0u8), // PMIC addr 0x60, reg 0x10, val 0xA0
            (0x220, 0x60, 0x11, 0xB0),       // Different register, different voltage
            (0x240, 0x62, 0x20, 0xC0),       // PMIC addr 0x62 (alternate)
            (0x260, 0x60, 0x30, 0xFF),       // Max voltage setting
            (0x280, 0x62, 0x00, 0x50),       // Min register address
            (0x2A0, 0x60, 0x7F, 0x01),       // Max register address boundary
        ];

        for &(offset, addr, reg, val) in &pmic_sequences {
            if offset + 3 < size {
                data[offset] = addr;
                data[offset + 1] = reg;
                data[offset + 2] = val;
            }
        }

        // Also place x86 DVFS pattern: WRMSR with MSR 0x199 (IA32_PERF_CTL)
        // to show cross-platform voltage attack
        let x86_base = 0x1000;
        // MOV ECX, 0x199
        data[x86_base] = 0xB9;
        data[x86_base + 1] = 0x99;
        data[x86_base + 2] = 0x01;
        data[x86_base + 3] = 0x00;
        data[x86_base + 4] = 0x00;
        // WRMSR
        data[x86_base + 5] = 0x0F;
        data[x86_base + 6] = 0x30;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "voltage_glitch".to_string(),
            min_severity: Severity::High,
        }]
    }
}
