use std::path::Path;

use anyhow::Result;

use crate::payloads::create_all_payloads;
use crate::{Arch, PayloadConfig};

pub fn generate_corpus(output_dir: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(output_dir)?;
    let payloads = create_all_payloads();
    let mut generated = Vec::new();

    for payload in &payloads {
        let config = PayloadConfig {
            arch: payload.arch(),
            size: 0x10000,
        };

        // Generate malicious variant
        let data = payload.generate(&config)?;
        let malicious_name = format!("malicious_{}.bin", payload.name());
        let malicious_path = output_dir.join(&malicious_name);
        std::fs::write(&malicious_path, &data)?;
        generated.push(malicious_name);

        // Generate clean variant (just zeros of same size)
        let clean_name = format!("clean_{}.bin", payload.name());
        let clean_path = output_dir.join(&clean_name);
        std::fs::write(&clean_path, vec![0u8; data.len()])?;
        generated.push(clean_name);
    }

    // Generate arch-specific variants
    for payload in &payloads {
        if payload.name() == "trampoline" {
            let config_arm = PayloadConfig {
                arch: Arch::Aarch64,
                size: 0x10000,
            };
            let data = payload.generate(&config_arm)?;
            let name = "malicious_trampoline_aarch64.bin".to_string();
            std::fs::write(output_dir.join(&name), &data)?;
            generated.push(name);
        }
    }

    Ok(generated)
}
