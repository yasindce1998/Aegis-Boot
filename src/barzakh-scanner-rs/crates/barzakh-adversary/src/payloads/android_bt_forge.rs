use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidBtForgePayload;

impl Payload for AndroidBtForgePayload {
    fn name(&self) -> &str {
        "android_bt_forge"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Inclusion proof with leaf_index marker
        let inclusion_offset = 0x00;
        let leaf_marker = b"leaf_index";
        data[inclusion_offset..inclusion_offset + leaf_marker.len()].copy_from_slice(leaf_marker);

        // Merkle path nodes with deliberate repeated hashes (forgery indicator)
        let hash_offset = inclusion_offset + 32;
        // Node prefix byte
        data[hash_offset] = 0x01; // MERKLE_NODE_PREFIX
                                  // First 32-byte hash
        for i in 0..32 {
            data[hash_offset + 1 + i] = 0xAA;
        }
        // Second node with same hash (repeated = forged)
        data[hash_offset + 33] = 0x01;
        for i in 0..32 {
            data[hash_offset + 34 + i] = 0xAA;
        }
        // Third node
        data[hash_offset + 66] = 0x00; // MERKLE_LEAF_PREFIX
        for i in 0..32 {
            data[hash_offset + 67 + i] = 0xBB;
        }

        // SignedTreeHead with zeroed root hash at offset 0x400
        let sth_offset = 0x400;
        let tree_marker = b"tree_size";
        data[sth_offset..sth_offset + tree_marker.len()].copy_from_slice(tree_marker);

        // Tree size value
        let mut cursor = std::io::Cursor::new(&mut data[sth_offset + 16..sth_offset + 24]);
        cursor.write_u64::<LittleEndian>(1_000_000)?;

        // Zeroed root hash at offset 64 from tree_size marker (already zero)

        // Consistency proof with empty data at offset 0x600
        let cons_offset = 0x600;
        let cons_marker = b"consistency";
        data[cons_offset..cons_offset + cons_marker.len()].copy_from_slice(cons_marker);
        // Proof data area at +16 is all zeros (empty/forged consistency proof)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_binary_transparency".to_string(),
            min_severity: Severity::High,
        }]
    }
}
