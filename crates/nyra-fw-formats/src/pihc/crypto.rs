//! Known HiChip 3-key block-cipher hypothesis from the user's phase-01 decoder.
//! This is a format-specific compatibility transform, NOT a general cryptographic primitive.
use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use nyra_fw_core::{FwError, Result};
use serde::{Deserialize, Serialize};

const KEYS: [[u8; 16]; 3] = [
    *b"@Hichip+1208/pkg",
    *b"$Hichip-1208%aes",
    *b"#Hichip*1208=key",
];
const BLOCK: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoVariant {
    pub phase: u8,
    pub rotation: u8,
}

impl CryptoVariant {
    pub const PHASE01: Self = Self {
        phase: 1,
        rotation: 0,
    };
    pub fn validate(self) -> Result<Self> {
        if self.phase >= 16 || self.rotation >= 3 {
            return Err(FwError::Config("phase must be 0..15; rotation 0..2".into()));
        }
        Ok(self)
    }
    pub fn label(self) -> String {
        format!(
            "hichip-aes-ecb-xor3f:block1024:phase{}:rotation{}",
            self.phase, self.rotation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    Known(CryptoVariant),
    Probe,
}

/// Restore only the encrypted bytes overlapping one ZIP payload. AES ECB works
/// on complete aligned blocks from the original archive, not entry-relative bytes.
pub fn restore_payload(
    archive: &[u8],
    start: usize,
    size: usize,
    variant: CryptoVariant,
) -> Result<Vec<u8>> {
    let variant = variant.validate()?;
    let end = start
        .checked_add(size)
        .filter(|&v| v <= archive.len())
        .ok_or_else(|| FwError::Invalid("payload outside archive".into()))?;
    let mut out = archive[start..end].to_vec();
    if size == 0 {
        return Ok(out);
    }
    for index in start / BLOCK..=(end - 1) / BLOCK {
        if index % 16 != variant.phase as usize {
            continue;
        }
        let chunk_start = index * BLOCK;
        let chunk_end = (chunk_start + BLOCK).min(archive.len());
        let aligned_end = chunk_start + (chunk_end - chunk_start) / 16 * 16;
        if aligned_end <= chunk_start {
            continue;
        }
        let key_index =
            ((index - variant.phase as usize) / 16 + variant.rotation as usize) % KEYS.len();
        let cipher = Aes128::new_from_slice(&KEYS[key_index])
            .map_err(|_| FwError::Config("AES key length".into()))?;
        let mut decrypted = archive[chunk_start..aligned_end].to_vec();
        for block in decrypted.chunks_exact_mut(16) {
            let mut aes_block = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut aes_block);
            block.copy_from_slice(&aes_block);
        }
        let left = start.max(chunk_start);
        let right = end.min(aligned_end);
        for absolute in left..right {
            out[absolute - start] = decrypted[absolute - chunk_start] ^ 0x3f;
        }
    }
    Ok(out)
}
