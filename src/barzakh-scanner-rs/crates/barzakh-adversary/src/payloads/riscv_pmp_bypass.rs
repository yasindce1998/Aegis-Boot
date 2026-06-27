use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RiscvPmpBypassPayload;

impl Payload for RiscvPmpBypassPayload {
    fn name(&self) -> &str {
        "riscv_pmp_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::RiscV64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // RISC-V PMP (Physical Memory Protection) bypass payload
        // Demonstrates a configuration where PMP is effectively disabled
        // or misconfigured to allow M-mode code execution from arbitrary memory

        // PMP configuration register dump (pmpcfg0..pmpcfg3)
        // Each byte in pmpcfg controls one PMP entry:
        //   [7] L (lock) | [6:5] reserved | [4:3] A (address mode) | [2] X | [1] W | [0] R
        let pmp_offset = 0x100;

        // pmpcfg0: all entries L=0, A=NAPOT(0b11), RWX(0b111) = 0x1F per byte
        // This is the exploit: unlocked entries covering full address space with full perms
        for i in 0..8 {
            data[pmp_offset + i] = 0x1F; // L=0, A=NAPOT, R=1, W=1, X=1
        }
        // pmpcfg2: same pattern
        for i in 0..8 {
            data[pmp_offset + 8 + i] = 0x1F;
        }

        // pmpaddr values: NAPOT with all 1s = covers entire 64-bit address space
        // pmpaddr0 = 0x1FFFFFFFFFFFFFFF (NAPOT covering 2^64 bytes)
        let addr_offset = 0x140;
        for i in 0..16 {
            let mut cursor =
                std::io::Cursor::new(&mut data[addr_offset + i * 8..addr_offset + i * 8 + 8]);
            cursor.write_u64::<LittleEndian>(0x1FFF_FFFF_FFFF_FFFF)?;
        }

        // Code pattern that writes these PMP values (CSR write sequence)
        let code_offset = 0x200;

        // csrw pmpcfg0, a0
        let mut cursor = std::io::Cursor::new(&mut data[code_offset..code_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x3A0_51073)?; // csrw 0x3A0, a0

        // csrw pmpcfg2, a1
        let mut cursor = std::io::Cursor::new(&mut data[code_offset + 4..code_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x3A2_59073)?; // csrw 0x3A2, a1

        // csrw pmpaddr0, a2 (covers full address space)
        let mut cursor = std::io::Cursor::new(&mut data[code_offset + 8..code_offset + 12]);
        cursor.write_u32::<LittleEndian>(0x3B0_61073)?; // csrw 0x3B0, a2

        // M-mode code region at offset 0x400 marked as RWX
        // This simulates exploitable M-mode firmware that can be written to
        let mmode_offset = 0x400;
        // NOP sled (RISC-V NOP = ADDI x0, x0, 0 = 0x00000013)
        for i in 0..32 {
            let mut cursor =
                std::io::Cursor::new(&mut data[mmode_offset + i * 4..mmode_offset + i * 4 + 4]);
            cursor.write_u32::<LittleEndian>(0x0000_0013)?;
        }
        // Followed by MRET (return from M-mode trap) — indicates this is M-mode code
        let mret_offset = mmode_offset + 128;
        let mut cursor = std::io::Cursor::new(&mut data[mret_offset..mret_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x3020_0073)?; // mret

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pmp_bypass".to_string(),
            min_severity: Severity::High,
        }]
    }
}
