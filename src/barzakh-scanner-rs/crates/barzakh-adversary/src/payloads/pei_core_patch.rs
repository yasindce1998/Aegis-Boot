use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PeiCorePatchPayload;

impl Payload for PeiCorePatchPayload {
    fn name(&self) -> &str {
        "pei_core_patch"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // EFI Firmware Volume header
        let fv_offset = 0x000;
        // FileSystemGuid — EFI_FIRMWARE_FILE_SYSTEM2_GUID
        let fs_guid: [u8; 16] = [
            0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F, 0x99, 0x35, 0x89, 0x61, 0x85, 0xC3,
            0x2D, 0xD3,
        ];
        data[fv_offset + 16..fv_offset + 32].copy_from_slice(&fs_guid);
        let fv_length = size as u64;
        data[fv_offset + 32..fv_offset + 40].copy_from_slice(&fv_length.to_le_bytes());
        data[fv_offset + 40..fv_offset + 44].copy_from_slice(b"_FVH");
        data[fv_offset + 48..fv_offset + 50].copy_from_slice(&0x0048u16.to_le_bytes());

        // PEI Core FFS file header
        let ffs_offset = 0x0048;
        // File GUID — PEI Core GUID {52C05B14-0B98-496c-BC3B-04B50211D680}
        let pei_core_guid: [u8; 16] = [
            0x14, 0x5B, 0xC0, 0x52, 0x98, 0x0B, 0x6C, 0x49, 0xBC, 0x3B, 0x04, 0xB5, 0x02, 0x11,
            0xD6, 0x80,
        ];
        data[ffs_offset..ffs_offset + 16].copy_from_slice(&pei_core_guid);
        // Integrity check
        data[ffs_offset + 16] = 0xAA;
        data[ffs_offset + 17] = 0x55;
        // File type = EFI_FV_FILETYPE_PEI_CORE (0x04)
        data[ffs_offset + 18] = 0x04;
        // Attributes
        data[ffs_offset + 19] = 0x00;
        // File size (3 bytes)
        let file_size: u32 = 0x1000;
        data[ffs_offset + 20] = (file_size & 0xFF) as u8;
        data[ffs_offset + 21] = ((file_size >> 8) & 0xFF) as u8;
        data[ffs_offset + 22] = ((file_size >> 16) & 0xFF) as u8;
        // State
        data[ffs_offset + 23] = 0xF8;

        // PE section within the PEI Core file
        let pe_section_offset = ffs_offset + 24;
        // Section size (3 bytes) + type
        let sec_size: u32 = 0x0F00;
        data[pe_section_offset] = (sec_size & 0xFF) as u8;
        data[pe_section_offset + 1] = ((sec_size >> 8) & 0xFF) as u8;
        data[pe_section_offset + 2] = ((sec_size >> 16) & 0xFF) as u8;
        data[pe_section_offset + 3] = 0x10; // EFI_SECTION_PE32

        // PE header with entry point OUTSIDE file boundaries
        let pe_offset = pe_section_offset + 4;
        // DOS Header "MZ"
        data[pe_offset] = 0x4D;
        data[pe_offset + 1] = 0x5A;
        // e_lfanew at offset 0x3C — pointer to PE signature
        let pe_sig_offset: u32 = 0x80;
        data[pe_offset + 0x3C..pe_offset + 0x40].copy_from_slice(&pe_sig_offset.to_le_bytes());
        // PE signature "PE\0\0"
        let pe_sig_abs = pe_offset + pe_sig_offset as usize;
        data[pe_sig_abs] = 0x50;
        data[pe_sig_abs + 1] = 0x45;
        // Machine = x86_64 (0x8664)
        data[pe_sig_abs + 4..pe_sig_abs + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        // SizeOfOptionalHeader
        data[pe_sig_abs + 20..pe_sig_abs + 22].copy_from_slice(&0x00F0u16.to_le_bytes());
        // Optional header magic (PE32+)
        data[pe_sig_abs + 24..pe_sig_abs + 26].copy_from_slice(&0x020Bu16.to_le_bytes());
        // AddressOfEntryPoint — way beyond file size
        let bad_entry: u32 = 0x00F00000;
        data[pe_sig_abs + 40..pe_sig_abs + 44].copy_from_slice(&bad_entry.to_le_bytes());
        // SizeOfImage
        data[pe_sig_abs + 80..pe_sig_abs + 84].copy_from_slice(&0x00002000u32.to_le_bytes());

        // RAW section (type 0x19) with high-entropy data (encrypted implant simulation)
        let raw_section_offset = 0x1800;
        let raw_sec_size: u32 = 0x400;
        data[raw_section_offset] = (raw_sec_size & 0xFF) as u8;
        data[raw_section_offset + 1] = ((raw_sec_size >> 8) & 0xFF) as u8;
        data[raw_section_offset + 2] = ((raw_sec_size >> 16) & 0xFF) as u8;
        data[raw_section_offset + 3] = 0x19; // EFI_SECTION_RAW

        // Fill with high-entropy pseudo-random data
        let raw_data_start = raw_section_offset + 4;
        let mut state: u32 = 0xDEADBEEF;
        for i in 0..(raw_sec_size as usize - 4).min(size - raw_data_start) {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            data[raw_data_start + i] = ((state >> 16) & 0xFF) as u8;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pei_implant".to_string(),
            min_severity: Severity::High,
        }]
    }
}
