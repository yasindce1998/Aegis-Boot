use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapEntry {
    pub payload_name: String,
    pub expected_detectors: Vec<String>,
    pub missed_detectors: Vec<String>,
    pub mutation_variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapReport {
    pub entries: Vec<GapEntry>,
    pub undetected_categories: Vec<String>,
    pub total_payloads: usize,
    pub total_gaps: usize,
    pub coverage_pct: f64,
}

impl GapReport {
    pub fn from_entries(entries: Vec<GapEntry>, total_payloads: usize) -> Self {
        let total_gaps = entries.len();
        let coverage_pct = if total_payloads > 0 {
            (total_payloads - total_gaps) as f64 / total_payloads as f64 * 100.0
        } else {
            100.0
        };

        let mut categories: Vec<String> = entries
            .iter()
            .flat_map(|e| e.missed_detectors.clone())
            .collect();
        categories.sort();
        categories.dedup();

        Self {
            entries,
            undetected_categories: categories,
            total_payloads,
            total_gaps,
            coverage_pct,
        }
    }
}
