use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

// EFI_IMAGE_SECURITY_DATABASE_GUID (vendor GUID of the dbx variable).
const DBX_GUID: [u8; 16] = [
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
];
// EFI_CERT_SHA256_GUID (the usual dbx SignatureType).
const SHA256_TYPE: [u8; 16] = [
    0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40, 0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28,
];

/// Emits an NVRAM record for the Secure Boot `dbx` forbidden-signature database
/// that has been rolled back: the EFI_SIGNATURE_LIST is empty (header-only) and
/// the authenticated timestamp predates the modern revocation set. This models
/// the BlackLotus-class downgrade where a stale, signed dbx is replayed so the
/// platform once again trusts revoked bootloaders.
pub struct DbxRollbackPayload;

impl Payload for DbxRollbackPayload {
    fn name(&self) -> &str {
        "dbx_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        let mut rec: Vec<u8> = Vec::new();
        // Variable name "dbx" (UTF-16LE) + terminator.
        rec.extend_from_slice(&[0x64, 0x00, 0x62, 0x00, 0x78, 0x00, 0x00, 0x00]);
        // VendorGuid.
        rec.extend_from_slice(&DBX_GUID);
        // EFI_SIGNATURE_LIST: SignatureType, then an empty-list header.
        rec.extend_from_slice(&SHA256_TYPE);
        rec.extend_from_slice(&0x1Cu32.to_le_bytes()); // SignatureListSize == header only
        rec.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
        rec.extend_from_slice(&0x30u32.to_le_bytes()); // SignatureSize
                                                       // EFI_TIME with a stale year (rollback).
        rec.extend_from_slice(&2011u16.to_le_bytes()); // Year
        rec.push(1); // Month
        rec.push(1); // Day
        rec.extend_from_slice(&[0u8; 12]); // Hour..Pad2 (rest of EFI_TIME)

        // Place the record at a non-zero offset within the firmware image.
        let at = 0x100;
        let end = (at + rec.len()).min(size);
        data[at..end].copy_from_slice(&rec[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "secureboot_dbx".to_string(),
            min_severity: Severity::High,
        }]
    }
}
