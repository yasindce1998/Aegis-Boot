use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use barzakh_core::BarzakhScanner;

use crate::Payload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub payload_name: String,
    pub detected: bool,
    pub expected_findings: usize,
    pub matched_findings: usize,
    pub extra_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub results: Vec<ValidationResult>,
    pub total_payloads: usize,
    pub detected_count: usize,
    pub missed_count: usize,
    pub true_positive_rate: f64,
}

impl ValidationReport {
    pub fn from_results(results: Vec<ValidationResult>) -> Self {
        let total_payloads = results.len();
        let detected_count = results.iter().filter(|r| r.detected).count();
        let missed_count = total_payloads - detected_count;
        let true_positive_rate = if total_payloads > 0 {
            detected_count as f64 / total_payloads as f64
        } else {
            0.0
        };

        Self {
            results,
            total_payloads,
            detected_count,
            missed_count,
            true_positive_rate,
        }
    }
}

pub fn validate_payload(payload: &dyn Payload, dump_path: &Path) -> Result<ValidationResult> {
    let mut scanner = BarzakhScanner::new(None);
    let scan_result = scanner.scan(dump_path, None);

    let expected = payload.expected_detections();
    let mut matched = 0;

    for exp in &expected {
        let found = scan_result
            .findings
            .iter()
            .any(|f| f.detector == exp.detector && f.severity >= exp.min_severity);
        if found {
            matched += 1;
        }
    }

    let extra = scan_result
        .findings
        .iter()
        .filter(|f| !expected.iter().any(|e| e.detector == f.detector))
        .count();

    Ok(ValidationResult {
        payload_name: payload.name().to_string(),
        detected: matched > 0,
        expected_findings: expected.len(),
        matched_findings: matched,
        extra_findings: extra,
    })
}

pub fn validate_all(payloads: &[Box<dyn Payload>], dump_dir: &Path) -> Result<ValidationReport> {
    let mut results = Vec::new();

    for payload in payloads {
        let dump_path = dump_dir.join(format!("malicious_{}.bin", payload.name()));
        if dump_path.exists() {
            results.push(validate_payload(payload.as_ref(), &dump_path)?);
        }
    }

    Ok(ValidationReport::from_results(results))
}
