use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IdracSpiLateralPayload;

impl Payload for IdracSpiLateralPayload {
    fn name(&self) -> &str {
        "idrac_spi_lateral"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // iDRAC firmware header marker
        let idrac_offset = 0x0;
        let idrac_magic = b"iDRAC";
        data[idrac_offset..idrac_offset + idrac_magic.len()].copy_from_slice(idrac_magic);

        // iDRAC version (9.x vulnerable series)
        let version_offset = 0x10;
        let version = b"iDRAC9-6.10.00";
        data[version_offset..version_offset + version.len()].copy_from_slice(version);

        // Redfish API endpoint for host BIOS update via iDRAC
        let redfish_offset = 0x100;
        let redfish_path = b"/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/DellManager.SetAttribute";
        data[redfish_offset..redfish_offset + redfish_path.len()].copy_from_slice(redfish_path);

        // SPI flash descriptor region access from BMC side
        let spi_offset = 0x300;
        // Intel SPI descriptor magic
        let spi_magic: [u8; 4] = [0x5A, 0xA5, 0xF0, 0x0F];
        data[spi_offset..spi_offset + 4].copy_from_slice(&spi_magic);

        // Master Access grants - BMC has write access to BIOS region
        let master_offset = 0x310;
        // FLMSTR3 (BMC/GBE master) with BIOS region write enabled
        let bmc_master: u32 = 0x00A00B00; // Write access to region 0 (descriptor) + region 1 (BIOS)
        data[master_offset..master_offset + 4].copy_from_slice(&bmc_master.to_le_bytes());

        // iDRAC RACADM command injection for SPI write
        let racadm_offset = 0x500;
        let racadm_cmd = b"racadm set BIOS.SpiAccess.Enable 1";
        data[racadm_offset..racadm_offset + racadm_cmd.len()].copy_from_slice(racadm_cmd);

        // Cross-domain bridge: BMC IPMI to host LPC/SPI bus
        let bridge_offset = 0x700;
        // IPMI NetFn for OEM Dell commands
        data[bridge_offset] = 0x30; // Dell OEM NetFn
        data[bridge_offset + 1] = 0xCE; // Dell SPI flash write command
        // Target region: BIOS flash
        data[bridge_offset + 4] = 0x01; // Region 1 = BIOS

        // PCH SPI controller BAR address (direct hardware access)
        let pch_offset = 0x900;
        let spibar: u32 = 0xFE010000; // Typical SPIBAR address
        data[pch_offset..pch_offset + 4].copy_from_slice(&spibar.to_le_bytes());

        // Write enable sequence
        data[pch_offset + 8] = 0x06; // SPI WREN (Write Enable)
        data[pch_offset + 9] = 0x02; // SPI PP (Page Program)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "idrac_spi".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
