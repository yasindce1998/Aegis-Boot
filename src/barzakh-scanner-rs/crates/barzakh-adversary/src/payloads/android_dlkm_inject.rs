use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidDlkmInjectPayload;

impl Payload for AndroidDlkmInjectPayload {
    fn name(&self) -> &str {
        "android_dlkm_inject"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // EROFS superblock magic at offset 0x400 (standard superblock offset)
        let sb_offset = 0x400;
        data[sb_offset] = 0xE0;
        data[sb_offset + 1] = 0xF5;
        data[sb_offset + 2] = 0xE1;
        data[sb_offset + 3] = 0xE2;

        // EROFS version
        let mut cursor = std::io::Cursor::new(&mut data[sb_offset + 4..sb_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x0001)?;

        // Injected ELF kernel module at offset 0x1000
        let elf_offset = 0x1000;
        // ELF magic
        data[elf_offset] = 0x7F;
        data[elf_offset + 1] = 0x45; // E
        data[elf_offset + 2] = 0x4C; // L
        data[elf_offset + 3] = 0x46; // F

        // ELF class: 64-bit
        data[elf_offset + 4] = 0x02;
        // ELF data: little-endian
        data[elf_offset + 5] = 0x01;
        // ELF machine: AArch64
        data[elf_offset + 18] = 0xB7;

        // init_module symbol (marks this as a loadable kernel module)
        let sym_offset = elf_offset + 0x100;
        let init_mod = b"init_module";
        data[sym_offset..sym_offset + init_mod.len()].copy_from_slice(init_mod);

        // NO module signature trailer — this module is unsigned
        // Legitimate modules have "~Module signature appended" marker

        // dm-verity metadata with disabled flag
        let verity_offset = 0x3000;
        let verity_magic = b"verity\x00\x00";
        data[verity_offset..verity_offset + verity_magic.len()].copy_from_slice(verity_magic);

        // Verity disabled flag (byte 0x02 in header region)
        data[verity_offset + 8] = 0x02;

        // Zeroed salt (32 bytes at offset +32 from verity magic, already zero)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_vendor_dlkm".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
