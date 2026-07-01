use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidChainBreakPayload;

impl Payload for AndroidChainBreakPayload {
    fn name(&self) -> &str {
        "android_chain_break"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x400);
        let mut data = vec![0u8; size];

        // pKVM present but unsigned (zeroed signature at +0x20)
        let pkvm_magic: [u8; 4] = [0x70, 0x76, 0x6D, 0x66]; // "pvmf"
        data[0x000..0x004].copy_from_slice(&pkvm_magic);
        // sig at 0x020..0x040 remains zeroed

        // DICE present but zeroed UDS (broken chain derivation)
        let dice_magic: [u8; 4] = [0x44, 0x49, 0x43, 0x45]; // "DICE"
        data[0x100..0x104].copy_from_slice(&dice_magic);
        // UDS at 0x110..0x130 remains zeroed

        // GKI present but unsigned (no boot_signature)
        let android_magic: [u8; 8] = [0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x21]; // "ANDROID!"
        data[0x200..0x208].copy_from_slice(&android_magic);
        // boot_sig at 0x230..0x240 remains zeroed

        // Trusty present but unsigned
        let trusty_magic: [u8; 4] = [0x54, 0x52, 0x55, 0x53]; // "TRUS"
        data[0x300..0x304].copy_from_slice(&trusty_magic);
        // sig at 0x320..0x340 remains zeroed

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_chain_validator".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
