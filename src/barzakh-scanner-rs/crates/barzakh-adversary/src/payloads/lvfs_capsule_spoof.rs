use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct LvfsCapsuleSpoofPayload;

impl Payload for LvfsCapsuleSpoofPayload {
    fn name(&self) -> &str {
        "lvfs_capsule_spoof"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x8000);
        let mut data = vec![0u8; size];

        // LVFS metadata XML header (cabinet archive format)
        let meta_offset = 0x0;
        let lvfs_header = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        data[meta_offset..meta_offset + lvfs_header.len()].copy_from_slice(lvfs_header);

        // fwupd metainfo component
        let component_offset = 0x100;
        let component = b"<component type=\"firmware\">";
        data[component_offset..component_offset + component.len()].copy_from_slice(component);

        // Spoofed firmware GUID targeting Dell/Lenovo/HP devices
        let guid_offset = 0x200;
        let spoofed_guid = b"<provides><firmware type=\"flashed\">230c8b18-8d9b-53ec-838b-6cfc0c5d4faa</firmware></provides>";
        data[guid_offset..guid_offset + spoofed_guid.len()].copy_from_slice(spoofed_guid);

        // Fake release version higher than current (triggers update)
        let release_offset = 0x400;
        let release = b"<release version=\"99.99.99\" date=\"2026-01-01\">";
        data[release_offset..release_offset + release.len()].copy_from_slice(release);

        // Checksum mismatch (metadata says one hash, payload has different content)
        let checksum_offset = 0x500;
        let checksum =
            b"<checksum type=\"sha256\">deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef</checksum>";
        data[checksum_offset..checksum_offset + checksum.len()].copy_from_slice(checksum);

        // Cabinet archive magic (MSCF)
        let cab_offset = 0x800;
        let cab_magic: [u8; 4] = [0x4D, 0x53, 0x43, 0x46]; // "MSCF"
        data[cab_offset..cab_offset + 4].copy_from_slice(&cab_magic);

        // Embedded firmware capsule with EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID
        let fmp_offset = 0x1000;
        let fmp_guid: [u8; 16] = [
            0xB1, 0x22, 0xA2, 0x6D, 0x4D, 0x1A, 0x1C, 0x41,
            0xAF, 0xC2, 0xC5, 0x86, 0x17, 0xF1, 0xC4, 0x24,
        ];
        data[fmp_offset..fmp_offset + 16].copy_from_slice(&fmp_guid);

        // fwupd remote configuration (spoofed metadata source)
        let remote_offset = 0x1800;
        let remote_url = b"https://fwupd.org/downloads/firmware.xml.gz";
        data[remote_offset..remote_offset + remote_url.len()].copy_from_slice(remote_url);

        // Jcat signature file marker (GPG detached sig for LVFS metadata)
        let jcat_offset = 0x2000;
        let jcat_magic = b"JCAT";
        data[jcat_offset..jcat_offset + jcat_magic.len()].copy_from_slice(jcat_magic);

        // Spoofed GPG key ID (not the real LVFS signing key)
        let gpg_offset = 0x2100;
        let fake_keyid: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        data[gpg_offset..gpg_offset + 8].copy_from_slice(&fake_keyid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "lvfs_integrity".to_string(),
            min_severity: Severity::High,
        }]
    }
}
