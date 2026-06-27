use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const DHCPV6_SOLICIT: u8 = 1;
const DHCPV6_ADVERTISE: u8 = 2;
const DHCPV6_REPLY: u8 = 7;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;
const OPTION_BOOTFILE_URL: u16 = 59;

pub struct PixiefailDetector;

impl Default for PixiefailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PixiefailDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_dhcpv6_options(&self, data: &[u8], base_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut pos = 0;

        while pos + 4 <= data.len() {
            let option_code = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap_or([0; 2]));
            let option_len =
                u16::from_be_bytes(data[pos + 2..pos + 4].try_into().unwrap_or([0; 2])) as usize;

            if option_len > data.len().saturating_sub(pos + 4) {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::Critical,
                        "PixieFail: DHCPv6 option length exceeds packet bounds",
                        &format!(
                            "DHCPv6 option {} at offset 0x{:08X} declares length {} but only {} bytes \
                             remain. This triggers CVE-2023-45229 (buffer overflow in EDK2 NetworkPkg).",
                            option_code, base_offset + pos, option_len,
                            data.len().saturating_sub(pos + 4)
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "option_code": option_code,
                        "declared_length": option_len,
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "cve": "CVE-2023-45229",
                    }))
                    .with_recommendation("Update EDK2/UEFI firmware to version with PixieFail patches"),
                );
                break;
            }

            if option_code == OPTION_DNS_SERVERS && !option_len.is_multiple_of(16) {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::High,
                        "PixieFail: Malformed DNS server option (CVE-2023-45231)",
                        &format!(
                            "DHCPv6 DNS Servers option at offset 0x{:08X} has length {} (not \
                             multiple of 16). Can trigger out-of-bounds read in IPv6 address parsing.",
                            base_offset + pos, option_len
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "option_len": option_len,
                        "cve": "CVE-2023-45231",
                    })),
                );
            }

            if option_code == OPTION_DOMAIN_LIST && option_len > 0 && pos + 4 < data.len() {
                let domain_data = &data[pos + 4..pos + 4 + option_len.min(data.len() - pos - 4)];
                if self.has_dns_compression_loop(domain_data) {
                    findings.push(
                        Finding::new(
                            "pixiefail",
                            Severity::Critical,
                            "PixieFail: DNS label compression creates infinite loop (CVE-2023-45232)",
                            &format!(
                                "DHCPv6 Domain List at offset 0x{:08X} contains DNS compression \
                                 pointers creating a cycle. Causes infinite loop in EDK2 DNS parser.",
                                base_offset + pos
                            ),
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", base_offset + pos),
                            "cve": "CVE-2023-45232",
                        }))
                        .with_recommendation("Patch EDK2 NetworkPkg to validate DNS compression pointers"),
                    );
                }
            }

            if option_code == OPTION_BOOTFILE_URL && option_len > 512 {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::High,
                        "PixieFail: Oversized Boot File URL option (CVE-2023-45235)",
                        &format!(
                            "DHCPv6 Boot File URL at offset 0x{:08X} has length {} which can \
                             overflow stack buffers in PXE boot handler.",
                            base_offset + pos,
                            option_len
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "option_len": option_len,
                        "cve": "CVE-2023-45235",
                    })),
                );
            }

            pos += 4 + option_len;
        }

        findings
    }

    fn has_dns_compression_loop(&self, data: &[u8]) -> bool {
        let mut pos = 0;
        let mut jumps = 0;
        while pos < data.len() {
            let label_len = data[pos] as usize;
            if label_len == 0 {
                break;
            }
            if label_len & 0xC0 == 0xC0 {
                jumps += 1;
                if jumps > 10 {
                    return true;
                }
                if pos + 1 >= data.len() {
                    break;
                }
                let ptr = (label_len & 0x3F) << 8 | data[pos + 1] as usize;
                if ptr >= data.len() {
                    break;
                }
                pos = ptr;
            } else {
                pos += 1 + label_len;
            }
        }
        false
    }
}

impl Detector for PixiefailDetector {
    fn name(&self) -> &str {
        "pixiefail"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        // Scan for DHCPv6 message structures
        let dhcpv6_msg_types = [DHCPV6_SOLICIT, DHCPV6_ADVERTISE, DHCPV6_REPLY];

        for i in 0..data.len().saturating_sub(8) {
            if dhcpv6_msg_types.contains(&data[i]) && data[i + 1..i + 4] != [0, 0, 0] {
                let option_start = i + 4;
                if option_start < data.len() {
                    findings.extend(self.check_dhcpv6_options(&data[option_start..], option_start));
                }
            }
        }

        // Check for IPv6 router advertisement anomalies (CVE-2023-45233)
        for i in 0..data.len().saturating_sub(16) {
            // ICMPv6 type 134 = Router Advertisement
            if data[i] == 134 && data[i + 1] == 0 && i + 16 < data.len() {
                let option_area = &data[i + 16..];
                if option_area.len() >= 4 {
                    let opt_len = option_area[1] as usize * 8;
                    if opt_len == 0 {
                        findings.push(
                            Finding::new(
                                "pixiefail",
                                Severity::High,
                                "PixieFail: IPv6 RA with zero-length option (CVE-2023-45233)",
                                &format!(
                                    "Router Advertisement at offset 0x{:08X} contains option \
                                         with length 0, causing infinite loop in option parser.",
                                    i
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "cve": "CVE-2023-45233",
                            })),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
