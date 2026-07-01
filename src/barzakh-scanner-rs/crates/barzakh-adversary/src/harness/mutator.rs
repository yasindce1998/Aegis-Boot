use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationStrategy {
    BitFlip,
    Truncate,
    Splice,
    ZeroRegion,
    HeaderSwap,
}

impl MutationStrategy {
    pub fn all() -> &'static [MutationStrategy] {
        &[
            MutationStrategy::BitFlip,
            MutationStrategy::Truncate,
            MutationStrategy::Splice,
            MutationStrategy::ZeroRegion,
            MutationStrategy::HeaderSwap,
        ]
    }

    pub fn name(&self) -> &str {
        match self {
            MutationStrategy::BitFlip => "bit_flip",
            MutationStrategy::Truncate => "truncate",
            MutationStrategy::Splice => "splice",
            MutationStrategy::ZeroRegion => "zero_region",
            MutationStrategy::HeaderSwap => "header_swap",
        }
    }
}

pub fn mutate_payload(data: &[u8], strategy: MutationStrategy) -> Vec<u8> {
    match strategy {
        MutationStrategy::BitFlip => mutate_bit_flip(data),
        MutationStrategy::Truncate => mutate_truncate(data),
        MutationStrategy::Splice => mutate_splice(data),
        MutationStrategy::ZeroRegion => mutate_zero_region(data),
        MutationStrategy::HeaderSwap => mutate_header_swap(data),
    }
}

fn mutate_bit_flip(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    if result.len() > 64 {
        let offset = 32 + (result.len() - 32) / 3;
        result[offset] ^= 0x01;
        if offset + 1 < result.len() {
            result[offset + 1] ^= 0x80;
        }
    }
    result
}

fn mutate_truncate(data: &[u8]) -> Vec<u8> {
    if data.len() > 128 {
        data[..data.len() * 3 / 4].to_vec()
    } else {
        data.to_vec()
    }
}

fn mutate_splice(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    if result.len() > 256 {
        let mid = result.len() / 2;
        let splice_data = vec![0xCC; 16];
        result.splice(mid..mid + 16.min(result.len() - mid), splice_data);
    }
    result
}

fn mutate_zero_region(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    if result.len() > 128 {
        let start = 64;
        let end = (start + 32).min(result.len());
        for byte in &mut result[start..end] {
            *byte = 0x00;
        }
    }
    result
}

fn mutate_header_swap(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    if result.len() > 64 {
        let header: Vec<u8> = result[..32].to_vec();
        let mid = result.len() / 2;
        let copy_len = 32.min(result.len() - mid);
        result[mid..mid + copy_len].copy_from_slice(&header[..copy_len]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_flip_modifies_data() {
        let data = vec![0xAA; 256];
        let mutated = mutate_payload(&data, MutationStrategy::BitFlip);
        assert_ne!(data, mutated);
        assert_eq!(data.len(), mutated.len());
    }

    #[test]
    fn truncate_shortens_data() {
        let data = vec![0xBB; 512];
        let mutated = mutate_payload(&data, MutationStrategy::Truncate);
        assert!(mutated.len() < data.len());
    }

    #[test]
    fn zero_region_zeroes_section() {
        let data = vec![0xFF; 256];
        let mutated = mutate_payload(&data, MutationStrategy::ZeroRegion);
        assert!(mutated[64..96].iter().all(|&b| b == 0x00));
    }
}
