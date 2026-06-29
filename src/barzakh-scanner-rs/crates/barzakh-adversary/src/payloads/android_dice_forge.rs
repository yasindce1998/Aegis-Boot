use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidDiceForgePayload;

impl Payload for AndroidDiceForgePayload {
    fn name(&self) -> &str {
        "android_dice_forge"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // COSE_Sign1 tag (major type 6, tag value 18 = 0xD2, followed by 0x84 for 4-element array)
        data[0] = 0xD2;
        data[1] = 0x84;

        // Protected header (empty bstr)
        data[2] = 0x40;

        // DiceCertChain marker
        let chain_offset = 0x10;
        let marker = b"DiceCertChain";
        data[chain_offset..chain_offset + marker.len()].copy_from_slice(marker);

        // CDI_Attest with zeroed code hash (indicates forged measurement)
        let cdi_offset = 0x100;
        let cdi_marker = b"CDI_Attest";
        data[cdi_offset..cdi_offset + cdi_marker.len()].copy_from_slice(cdi_marker);

        // The 32-byte code hash after CDI_Attest is all zeros (already zero)
        // This means the DICE chain was forged without measuring actual code

        // UDS (Unique Device Secret) with low entropy pattern
        let uds_offset = 0x200;
        let uds_marker = b"UDS";
        data[uds_offset..uds_offset + uds_marker.len()].copy_from_slice(uds_marker);

        // Fill UDS value with repeating pattern (low entropy = predictable)
        for i in 0..32 {
            data[uds_offset + 8 + i] = (i as u8) % 4;
        }

        // Second COSE_Sign1 in chain (forged intermediate cert)
        let cert2_offset = 0x400;
        data[cert2_offset] = 0xD2;
        data[cert2_offset + 1] = 0x84;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_dice".to_string(),
            min_severity: Severity::High,
        }]
    }
}
