use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553_544F4F42;
const BST_REVISION: u32 = 0x0002_0046; // UEFI 2.70
const BST_HEADER_SIZE: u32 = 24;
const NUM_BOOT_SERVICES: usize = 28;

pub struct BootServicesHookPayload;

impl Payload for BootServicesHookPayload {
    fn name(&self) -> &str {
        "boot_services_hook"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let table_offset = 0x1000;
        let total_size = table_offset + BST_HEADER_SIZE as usize + NUM_BOOT_SERVICES * 8 + 0x100;
        let size = config.size.max(total_size);
        let mut data = vec![0u8; size];

        let mut cursor = std::io::Cursor::new(&mut data[table_offset..]);

        // EFI_TABLE_HEADER: Signature (8) + Revision (4) + HeaderSize (4) + CRC32 (4) + Reserved (4)
        cursor.write_u64::<LittleEndian>(EFI_BOOT_SERVICES_SIGNATURE)?;
        cursor.write_u32::<LittleEndian>(BST_REVISION)?;
        cursor.write_u32::<LittleEndian>(BST_HEADER_SIZE)?;
        // Write a deliberately WRONG CRC32 to trigger CRC mismatch
        cursor.write_u32::<LittleEndian>(0xDEAD_BEEF)?;
        // Reserved
        cursor.write_u32::<LittleEndian>(0)?;

        // Write 28 function pointers
        // Most are in valid UEFI range, but hook 3 to suspicious addresses
        for i in 0..NUM_BOOT_SERVICES {
            let ptr: u64 = match i {
                // AllocatePool (index 5) — hooked to suspicious address
                5 => 0x0000_4000_DEAD_0000,
                // LoadImage (index 22) — hooked
                22 => 0x0000_7000_CAFE_0000,
                // ExitBootServices (index 26) — hooked
                26 => 0x0000_5000_BABE_0000,
                // All others — valid low-range address
                _ => 0x0000_0000_7E00_0000 + (i as u64 * 0x100),
            };
            cursor.write_u64::<LittleEndian>(ptr)?;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "hook".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
