use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct DellBiosConnectPayload;

impl Payload for DellBiosConnectPayload {
    fn name(&self) -> &str {
        "dell_bios_connect"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // Dell SupportAssist DXE GUID: network-fetching UEFI driver
        // Real GUID from Dell BIOSConnect module
        let dxe_guid: [u8; 16] = [
            0x4A, 0x44, 0x65, 0x6C, 0x6C, 0x42, 0x43, 0x6F,
            0x6E, 0x6E, 0x65, 0x63, 0x74, 0x44, 0x78, 0x65,
        ];
        data[0..16].copy_from_slice(&dxe_guid);

        // PE/COFF header for DXE driver
        let pe_offset = 0x80;
        data[pe_offset..pe_offset + 2].copy_from_slice(b"MZ");
        data[pe_offset + 0x3C..pe_offset + 0x40].copy_from_slice(&(pe_offset as u32 + 0x80).to_le_bytes());

        // Dell BIOSConnect marker string
        let marker_offset = 0x200;
        let connect_marker = b"DellBIOSConnect";
        data[marker_offset..marker_offset + connect_marker.len()].copy_from_slice(connect_marker);

        // TLS connection setup with HTTPS fetch (SupportAssist calls home)
        let tls_offset = 0x400;
        let tls_marker = b"TLS_RSA_WITH_AES_256_CBC_SHA";
        data[tls_offset..tls_offset + tls_marker.len()].copy_from_slice(tls_marker);

        // Spoofed X.509 certificate chain (self-signed root, mimicking Dell's CA)
        let cert_offset = 0x600;
        // ASN.1 SEQUENCE tag for X.509 cert
        data[cert_offset] = 0x30;
        data[cert_offset + 1] = 0x82;
        data[cert_offset + 2] = 0x03;
        data[cert_offset + 3] = 0x48;
        // Dell-like CN in cert subject
        let dell_cn = b"CN=Dell Inc Root CA";
        data[cert_offset + 0x20..cert_offset + 0x20 + dell_cn.len()].copy_from_slice(dell_cn);

        // Second cert in chain (intermediate) with mismatched issuer
        let intermediate_offset = 0xA00;
        data[intermediate_offset] = 0x30;
        data[intermediate_offset + 1] = 0x82;
        data[intermediate_offset + 2] = 0x02;
        data[intermediate_offset + 3] = 0xFF;
        let fake_issuer = b"CN=Dell Recovery Services";
        data[intermediate_offset + 0x20..intermediate_offset + 0x20 + fake_issuer.len()]
            .copy_from_slice(fake_issuer);

        // HTTP URL for BIOS recovery image fetch (unvalidated in vuln versions)
        let url_offset = 0xE00;
        let recovery_url = b"https://downloads.dell.com/bios/";
        data[url_offset..url_offset + recovery_url.len()].copy_from_slice(recovery_url);

        // SupportAssist version marker (vulnerable version range)
        let version_offset = 0xF00;
        let version_str = b"SupportAssist-3.11";
        data[version_offset..version_offset + version_str.len()].copy_from_slice(version_str);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "dell_bios_connect".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
