use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct InsydeSmmCapsulePayload;

impl Payload for InsydeSmmCapsulePayload {
    fn name(&self) -> &str {
        "insyde_smm_capsule"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // EFI_CAPSULE_HEADER
        let capsule_offset = 0x0;
        // Insyde H2O firmware update capsule GUID
        let insyde_capsule_guid: [u8; 16] = [
            0x4F, 0x1C, 0x52, 0x31, 0x5F, 0x93, 0xAE, 0x4F,
            0xB4, 0x11, 0xA2, 0x13, 0xB7, 0x64, 0xFF, 0xE5,
        ];
        data[capsule_offset..capsule_offset + 16].copy_from_slice(&insyde_capsule_guid);

        // Capsule header size
        let header_size: u32 = 0x1C;
        data[capsule_offset + 16..capsule_offset + 20].copy_from_slice(&header_size.to_le_bytes());

        // Capsule flags (POPULATE_SYSTEM_TABLE | PERSIST_ACROSS_RESET)
        let flags: u32 = 0x00030000;
        data[capsule_offset + 20..capsule_offset + 24].copy_from_slice(&flags.to_le_bytes());

        // Capsule image size (intentionally oversized to trigger SMM buffer overflow)
        let malicious_size: u32 = 0xFFFF0000;
        data[capsule_offset + 24..capsule_offset + 28].copy_from_slice(&malicious_size.to_le_bytes());

        // Insyde H2O IHISI (Insyde H2O Software Interface) SMM handler marker
        let ihisi_offset = 0x100;
        let ihisi_magic = b"$IHISI$";
        data[ihisi_offset..ihisi_offset + ihisi_magic.len()].copy_from_slice(ihisi_magic);

        // SMI command triggering capsule processing (SW SMI port 0xB2)
        let smi_offset = 0x200;
        data[smi_offset] = 0xB2; // SW SMI port
        data[smi_offset + 1] = 0x4F; // Insyde-specific SMI command for capsule update

        // Malformed capsule body that overflows SMRAM buffer
        // Length field claims small size but actual data exceeds SMRAM boundary
        let overflow_offset = 0x300;
        let claimed_size: u32 = 0x100; // claims 256 bytes
        data[overflow_offset..overflow_offset + 4].copy_from_slice(&claimed_size.to_le_bytes());

        // Shellcode payload placed at SMRAM overflow boundary
        let shellcode_offset = 0x500;
        // NOP sled + typical SMM shellcode prologue
        for i in 0..16 {
            data[shellcode_offset + i] = 0x90; // NOP
        }
        // MOV RSP, <SMRAM_base> pattern
        data[shellcode_offset + 16] = 0x48;
        data[shellcode_offset + 17] = 0xBC;

        // Insyde FlashProtect variable manipulation
        let flash_protect_offset = 0x700;
        let flash_protect_var = b"InsydeFlashProtect";
        data[flash_protect_offset..flash_protect_offset + flash_protect_var.len()]
            .copy_from_slice(flash_protect_var);
        // Disable flash protection
        data[flash_protect_offset + 0x20] = 0x00;

        // Acer-specific BIOS vendor string (Insyde H2O is commonly used by Acer)
        let vendor_offset = 0x800;
        let acer_vendor = b"Insyde Corp.";
        data[vendor_offset..vendor_offset + acer_vendor.len()].copy_from_slice(acer_vendor);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "insyde_smm".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
