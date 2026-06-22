use anyhow::Result;
use std::path::Path;

pub struct EspImageBuilder {
    size_mb: u32,
}

impl EspImageBuilder {
    pub fn new(size_mb: u32) -> Self {
        Self { size_mb }
    }

    pub fn build_with_payload(&self, payload: &[u8], output: &Path) -> Result<()> {
        // FAT12/16 ESP image with payload embedded as EFI binary
        // Minimal FAT structure: BPB + FAT + root dir + payload
        let sector_size: u32 = 512;
        let total_sectors = self.size_mb * 1024 * 1024 / sector_size;
        let mut image = vec![0u8; (total_sectors * sector_size) as usize];

        // Boot sector / BPB
        image[0] = 0xEB; // JMP short
        image[1] = 0x3C;
        image[2] = 0x90; // NOP
        image[3..11].copy_from_slice(b"BARZAKH ");

        // Bytes per sector
        image[11] = (sector_size & 0xFF) as u8;
        image[12] = (sector_size >> 8) as u8;

        // Sectors per cluster
        image[13] = 0x08;

        // Reserved sectors
        image[14] = 0x20;
        image[15] = 0x00;

        // Number of FATs
        image[16] = 0x02;

        // Total sectors 16-bit (0 = use 32-bit field)
        image[19] = 0x00;
        image[20] = 0x00;

        // Media type (fixed disk)
        image[21] = 0xF8;

        // Total sectors 32-bit
        let ts_bytes = total_sectors.to_le_bytes();
        image[32..36].copy_from_slice(&ts_bytes);

        // Signature
        image[510] = 0x55;
        image[511] = 0xAA;

        // Write payload into the data region
        let data_start = 0x20 * sector_size as usize;
        if data_start + payload.len() < image.len() {
            image[data_start..data_start + payload.len()].copy_from_slice(payload);
        }

        std::fs::write(output, &image)?;
        Ok(())
    }
}
