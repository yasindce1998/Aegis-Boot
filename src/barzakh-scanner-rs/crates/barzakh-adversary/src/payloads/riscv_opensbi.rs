use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RiscvOpensbiPayload;

impl Payload for RiscvOpensbiPayload {
    fn name(&self) -> &str {
        "riscv_opensbi"
    }

    fn arch(&self) -> Arch {
        Arch::RiscV64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // OpenSBI firmware image header
        let offset = 0x0;
        data[offset..offset + 8].copy_from_slice(b"OPENSBI\0");

        // Version field (v1.0)
        let mut cursor = std::io::Cursor::new(&mut data[offset + 8..offset + 12]);
        cursor.write_u32::<LittleEndian>(0x0001_0000)?;

        // SBI extension table at offset 0x100
        // Each entry: extension_id (u32) + handler_addr (u64)
        let ext_table = 0x100;

        // Extension 0x10 (SBI_EXT_BASE) — normal
        let mut cursor = std::io::Cursor::new(&mut data[ext_table..ext_table + 4]);
        cursor.write_u32::<LittleEndian>(0x10)?;
        let mut cursor = std::io::Cursor::new(&mut data[ext_table + 4..ext_table + 12]);
        cursor.write_u64::<LittleEndian>(0x8000_0000_0000_1000)?; // .text range

        // Extension 0x48534D (HSM) — redirected to user-allocated memory (malicious)
        let entry2 = ext_table + 12;
        let mut cursor = std::io::Cursor::new(&mut data[entry2..entry2 + 4]);
        cursor.write_u32::<LittleEndian>(0x0048_534D)?; // "HSM"
                                                        // Handler redirected outside .text — indicates ecall table hooking
        let mut cursor = std::io::Cursor::new(&mut data[entry2 + 4..entry2 + 12]);
        cursor.write_u64::<LittleEndian>(0xDEAD_0000_CAFE_0000)?;

        // Extension 0x535345 (SSE) — also redirected
        let entry3 = ext_table + 24;
        let mut cursor = std::io::Cursor::new(&mut data[entry3..entry3 + 4]);
        cursor.write_u32::<LittleEndian>(0x0053_5345)?; // "SSE"
        let mut cursor = std::io::Cursor::new(&mut data[entry3 + 4..entry3 + 12]);
        cursor.write_u64::<LittleEndian>(0xDEAD_0000_CAFE_1000)?;

        // mtvec CSR write pattern at offset 0x200
        // Indicates trap vector redirection to attacker-controlled address
        // RISC-V: csrrw zero, mtvec, t0 = 0x30529073
        let mtvec_offset = 0x200;
        let mut cursor = std::io::Cursor::new(&mut data[mtvec_offset..mtvec_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x3052_9073)?;

        // Load suspicious mtvec target into t0 first
        // LUI t0, 0xDEAD0 (upper 20 bits)
        let mut cursor = std::io::Cursor::new(&mut data[mtvec_offset + 4..mtvec_offset + 8]);
        cursor.write_u32::<LittleEndian>(0xDEAD_02B7)?;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "opensbi".to_string(),
            min_severity: Severity::High,
        }]
    }
}
