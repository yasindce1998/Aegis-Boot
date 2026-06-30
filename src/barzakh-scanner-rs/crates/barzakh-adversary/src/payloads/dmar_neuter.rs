use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits firmware carrying a VT-d `DMAR` ACPI table that has been "neutered":
/// its declared length is exactly the 48-byte fixed prologue, so it enumerates
/// **zero** DRHD (DMA Remapping Hardware Definition) units. The OS therefore
/// believes the platform has no IOMMU to program — the silent pre-boot DMA
/// exposure exploited by Thunderspy / PCILeech-style attacks.
pub struct DmarNeuterPayload;

impl Payload for DmarNeuterPayload {
    fn name(&self) -> &str {
        "dmar_neuter"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // DMAR table at offset 0, total length = 48 (header + HostAddressWidth +
        // Flags + reserved), with no trailing DRHD remapping structures.
        const DMAR_LEN: u32 = 48;
        data[0x00..0x04].copy_from_slice(b"DMAR");
        data[0x04..0x08].copy_from_slice(&DMAR_LEN.to_le_bytes());
        data[0x08] = 0x01; // Revision
        data[0x09] = 0x00; // Checksum (recomputed below)
        data[0x0A..0x10].copy_from_slice(b"BRZKH0");
        data[0x10..0x18].copy_from_slice(b"NEUTERED");
        data[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
        data[0x1C..0x20].copy_from_slice(b"BRZK"); // Creator ID
        data[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // Creator Revision
        data[0x24] = 0x27; // Host Address Width (39-bit)
        data[0x25] = 0x00; // Flags: INTR_REMAP cleared
                           // 0x26..0x30: reserved (already zero); table ends at 0x30 (48).

        // Make the ACPI checksum valid (sum of table bytes == 0 mod 256) so the
        // table reads as well-formed and the finding is unambiguously structural.
        let sum: u8 = data[0..DMAR_LEN as usize]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        data[0x09] = (0u8).wrapping_sub(sum);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "iommu_dmar".to_string(),
            min_severity: Severity::High,
        }]
    }
}
