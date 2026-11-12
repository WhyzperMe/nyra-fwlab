//! Block entropy summary: a heuristic that cannot tell compression from encryption.
use super::Entropy;
use nyra_fw_core::{Result, budget::RunBudget};
use rayon::prelude::*;

pub(super) const ENTROPY_BLOCK: usize = 64 * 1024;

pub(super) fn entropy(raw: &[u8], run: &RunBudget) -> Result<Entropy> {
    run.checkpoint()?;
    let (high, uniform) = raw
        .par_chunks(ENTROPY_BLOCK)
        .map(|block| {
            let mut histogram = [0u32; 256];
            for &byte in block {
                histogram[usize::from(byte)] += 1;
            }
            let length = block.len() as f64;
            let bits: f64 = histogram
                .iter()
                .filter(|&&count| count != 0)
                .map(|&count| {
                    let p = f64::from(count) / length;
                    -p * p.log2()
                })
                .sum();
            let full = block.len() == ENTROPY_BLOCK;
            (
                u64::from(full && bits >= 7.5),
                u64::from(histogram.iter().any(|&count| count as usize == block.len())),
            )
        })
        .reduce(|| (0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    run.checkpoint()?;
    Ok(Entropy {
        block_bytes: ENTROPY_BLOCK as u32,
        blocks: raw.len().div_ceil(ENTROPY_BLOCK) as u64,
        high_entropy_blocks: high,
        uniform_fill_blocks: uniform,
    })
}
