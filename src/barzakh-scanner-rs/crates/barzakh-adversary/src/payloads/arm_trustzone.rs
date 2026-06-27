use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ArmTrustzonePayload;

impl Payload for ArmTrustzonePayload {
    fn name(&self) -> &str {
        "arm_trustzone"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // OP-TEE Trusted Application header with tampering indicators
        // TA magic "OPTE" at offset 0x100
        let offset = 0x100;
        data[offset] = b'O';
        data[offset + 1] = b'P';
        data[offset + 2] = b'T';
        data[offset + 3] = b'E';

        // TA version (v2)
        data[offset + 4] = 0x02;

        // Load address outside secure world range (> 0x1_0000_0000)
        // This indicates the TA has been patched to load into normal world memory
        let mut cursor = std::io::Cursor::new(&mut data[offset + 8..offset + 16]);
        cursor.write_u64::<LittleEndian>(0x0000_0002_8000_0000)?;

        // TA code size (suspiciously large — indicates injected payload)
        let mut cursor = std::io::Cursor::new(&mut data[offset + 16..offset + 20]);
        cursor.write_u32::<LittleEndian>(0x0080_0000)?;

        // SMC instruction pattern at offset 0x200 — SMC #0 (HVC into secure monitor)
        // ARM64 encoding: 0xD4000003 (SMC #0)
        let smc_offset = 0x200;
        let mut cursor = std::io::Cursor::new(&mut data[smc_offset..smc_offset + 4]);
        cursor.write_u32::<LittleEndian>(0xD400_0003)?;

        // Forged service ID in x0 register setup (MOV X0, #0x1FF — non-standard service)
        // ARM64: MOV X0, #0x1FF = 0xD2803FE0
        let mut cursor = std::io::Cursor::new(&mut data[smc_offset + 4..smc_offset + 8]);
        cursor.write_u32::<LittleEndian>(0xD280_3FE0)?;

        // Second SMC call with different service ID pattern
        let smc_offset2 = 0x300;
        let mut cursor = std::io::Cursor::new(&mut data[smc_offset2..smc_offset2 + 4]);
        cursor.write_u32::<LittleEndian>(0xD400_0003)?;
        // MOV X0, #0xC200 (suspicious PSCI/power management service override)
        let mut cursor = std::io::Cursor::new(&mut data[smc_offset2 + 4..smc_offset2 + 8]);
        cursor.write_u32::<LittleEndian>(0xD298_4000)?;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "arm_trustzone".to_string(),
            min_severity: Severity::High,
        }]
    }
}
