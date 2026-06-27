use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BootGuardBypassPayload;

impl Payload for BootGuardBypassPayload {
    fn name(&self) -> &str {
        "boot_guard_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // ACM (Authenticated Code Module) header with invalid size
        let acm_offset = 0x000;
        // Module type = 0x0002 (ACM)
        data[acm_offset..acm_offset + 2].copy_from_slice(&0x0002u16.to_le_bytes());
        // Module sub-type
        data[acm_offset + 2..acm_offset + 4].copy_from_slice(&0x0001u16.to_le_bytes());
        // Header length (in DWORDs) — intentionally smaller than min
        data[acm_offset + 4..acm_offset + 8].copy_from_slice(&0x10u32.to_le_bytes());
        // Module ID
        data[acm_offset + 8..acm_offset + 12].copy_from_slice(&0x00000001u32.to_le_bytes());
        // Module size (in DWORDs) — exceeds available data
        let fake_module_size: u32 = 0x00100000; // 4MB in bytes when *4
        data[acm_offset + 12..acm_offset + 16].copy_from_slice(&fake_module_size.to_le_bytes());
        // Intel vendor ID at offset +16
        data[acm_offset + 16..acm_offset + 20].copy_from_slice(&0x00008086u32.to_le_bytes());

        // Key Manifest structure "__KEYM__"
        let km_offset = 0x1000;
        data[km_offset..km_offset + 8]
            .copy_from_slice(&[0x5F, 0x5F, 0x4B, 0x45, 0x59, 0x4D, 0x5F, 0x5F]);
        // KM version = 2
        data[km_offset + 8] = 0x02;
        // KM SVN = 0 (rollback indicator)
        data[km_offset + 9] = 0x00;
        // KM ID
        data[km_offset + 10..km_offset + 12].copy_from_slice(&0x0001u16.to_le_bytes());

        // Boot Policy Manifest "__BPM__\0"
        let bpm_offset = 0x2000;
        data[bpm_offset..bpm_offset + 8]
            .copy_from_slice(&[0x5F, 0x5F, 0x42, 0x50, 0x4D, 0x5F, 0x5F, 0x00]);
        // BPM version = 1
        data[bpm_offset + 8] = 0x01;
        // BPM SVN = 0
        data[bpm_offset + 9] = 0x00;
        // IBB element with hash_size = 0 (verification disabled)
        let ibb_offset = bpm_offset + 16;
        data[ibb_offset] = 0x00;
        data[ibb_offset + 1] = 0x00;
        data[ibb_offset + 2] = 0x0B; // IBB element type marker
                                     // Fill IBB element
                                     // hash_size at offset +34 from IBB element = 0
        data[ibb_offset + 34..ibb_offset + 36].copy_from_slice(&0u16.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "boot_guard".to_string(),
            min_severity: Severity::High,
        }]
    }
}
