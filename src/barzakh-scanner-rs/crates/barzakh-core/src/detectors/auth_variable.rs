use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = [
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
];

const EFI_IMAGE_SECURITY_DATABASE_GUID: [u8; 16] = [
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
];

const EFI_VARIABLE_TIME_BASED_AUTH: u32 = 0x00000020;
const EFI_VARIABLE_APPEND_WRITE: u32 = 0x00000040;

pub struct AuthVariableDetector;

impl Default for AuthVariableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthVariableDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_authenticated_variables(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Search for EFI variable store structures
        for i in 0..data.len().saturating_sub(64) {
            // Look for known variable GUIDs
            if data[i..i + 16] == EFI_GLOBAL_VARIABLE_GUID
                || data[i..i + 16] == EFI_IMAGE_SECURITY_DATABASE_GUID
            {
                self.check_variable_at_offset(data, i, &mut findings);
            }
        }

        findings
    }

    fn check_variable_at_offset(
        &self,
        data: &[u8],
        guid_offset: usize,
        findings: &mut Vec<Finding>,
    ) {
        // Variable header typically precedes the GUID
        // UEFI variable structure: StartId(2) + State(1) + Reserved(1) + Attributes(4) + ...
        if guid_offset < 8 {
            return;
        }

        let var_start = guid_offset.saturating_sub(8);
        if var_start + 60 > data.len() {
            return;
        }

        let attributes = u32::from_le_bytes(
            data[var_start + 4..var_start + 8]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // Check for time-based authenticated variable without proper auth data
        if attributes & EFI_VARIABLE_TIME_BASED_AUTH != 0 {
            // Look for monotonic count / timestamp after variable name
            let name_start = guid_offset + 16;
            if name_start + 24 < data.len() {
                // EFI_VARIABLE_AUTHENTICATION_2 has a timestamp (16 bytes)
                let timestamp = &data[name_start..name_start + 16];
                let all_zero = timestamp.iter().all(|&b| b == 0);

                if all_zero {
                    findings.push(
                        Finding::new(
                            "auth_variable",
                            Severity::High,
                            "Authenticated variable with zeroed timestamp (replay possible)",
                            &format!(
                                "Authenticated variable at offset 0x{:08X} has all-zero timestamp. \
                                 This defeats time-based replay protection and may allow variable \
                                 content rollback.",
                                var_start
                            ),
                        )
                        .with_confidence(0.78)
                        .with_details(serde_json::json!({
                            "variable_offset": format!("0x{:08X}", var_start),
                            "attributes": format!("0x{:08X}", attributes),
                            "is_security_db": data[guid_offset..guid_offset + 16] == EFI_IMAGE_SECURITY_DATABASE_GUID,
                        }))
                        .with_recommendation(
                            "Re-provision variable with proper time-based authentication"
                        ),
                    );
                }
            }
        }

        // Check for security database variable without authentication attribute
        if data[guid_offset..guid_offset + 16] == EFI_IMAGE_SECURITY_DATABASE_GUID
            && attributes & EFI_VARIABLE_TIME_BASED_AUTH == 0
        {
            findings.push(
                Finding::new(
                    "auth_variable",
                    Severity::Critical,
                    "Security database variable without authentication",
                    &format!(
                        "Variable at offset 0x{:08X} uses the image security database GUID \
                             but lacks TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute. The db/dbx \
                             can be modified without cryptographic proof.",
                        var_start
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "variable_offset": format!("0x{:08X}", var_start),
                    "attributes": format!("0x{:08X}", attributes),
                }))
                .with_recommendation(
                    "Ensure PK, KEK, db, and dbx all require authenticated writes",
                ),
            );
        }

        // Check for append-write without authentication (allows unauthorized additions)
        if attributes & EFI_VARIABLE_APPEND_WRITE != 0
            && attributes & EFI_VARIABLE_TIME_BASED_AUTH == 0
        {
            findings.push(
                Finding::new(
                    "auth_variable",
                    Severity::Medium,
                    "Variable with APPEND_WRITE but no authentication requirement",
                    &format!(
                        "Variable at offset 0x{:08X} allows append writes without authentication. \
                         An attacker at runtime could append malicious data to this variable.",
                        var_start
                    ),
                )
                .with_confidence(0.65)
                .with_details(serde_json::json!({
                    "variable_offset": format!("0x{:08X}", var_start),
                    "attributes": format!("0x{:08X}", attributes),
                })),
            );
        }
    }

    fn check_monotonic_counter_rollback(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for monotonic count patterns (sequential 8-byte values)
        // A counter at 0 for PK/KEK/db variables is suspicious
        let pk_name = b"P\x00K\x00\x00\x00";
        let kek_name = b"K\x00E\x00K\x00\x00\x00";

        for i in 0..data.len().saturating_sub(pk_name.len() + 16) {
            if data[i..].starts_with(pk_name) || data[i..].starts_with(kek_name) {
                // Check for monotonic counter near the variable
                let search_start = i.saturating_sub(32);
                let search_end = (i + 64).min(data.len() - 8);
                for j in search_start..search_end {
                    let counter = u64::from_le_bytes(data[j..j + 8].try_into().unwrap_or([0; 8]));
                    if counter == 0 {
                        let is_pk = data[i..].starts_with(pk_name);
                        findings.push(
                            Finding::new(
                                "auth_variable",
                                Severity::High,
                                &format!(
                                    "Monotonic counter rollback on {} variable",
                                    if is_pk { "PK" } else { "KEK" }
                                ),
                                &format!(
                                    "{} variable at offset 0x{:08X} has monotonic counter at 0. \
                                     This allows replaying older variable values, potentially \
                                     re-enrolling revoked keys.",
                                    if is_pk {
                                        "Platform Key"
                                    } else {
                                        "Key Exchange Key"
                                    },
                                    i
                                ),
                            )
                            .with_confidence(0.72)
                            .with_details(serde_json::json!({
                                "variable_name": if is_pk { "PK" } else { "KEK" },
                                "offset": format!("0x{:08X}", i),
                                "counter_value": 0,
                            })),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }
}

impl Detector for AuthVariableDetector {
    fn name(&self) -> &str {
        "auth_variable"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_authenticated_variables(&data));
        findings.extend(self.check_monotonic_counter_rollback(&data));

        Ok(findings)
    }
}
