//! Bounded signature search over one region of bytes.
use super::{BOUNDS, CandidateKind};
use crate::{central::zip_end_bounds, magic};
use nyra_fw_core::{Result, budget::RunBudget};
use rayon::prelude::*;
use std::collections::BTreeMap;

pub(super) const SIGNATURES: &[(CandidateKind, &[u8])] = &[
    (CandidateKind::Pihc, magic::PIHC),
    (CandidateKind::Zip, magic::ZIP_LOCAL),
    (CandidateKind::Gzip, magic::GZIP_DEFLATE),
    (CandidateKind::SquashFs, magic::SQUASHFS),
    (CandidateKind::SquashFsBigEndian, magic::SQUASHFS_BIG_ENDIAN),
    (CandidateKind::UImage, magic::UIMAGE),
    (CandidateKind::Elf, magic::ELF),
    (CandidateKind::Fdt, magic::FDT),
    (CandidateKind::Ubi, magic::UBI_ERASE_COUNTER),
    (CandidateKind::Xz, magic::XZ),
    (CandidateKind::Bzip2, magic::BZIP2),
    (CandidateKind::Zstd, magic::ZSTD),
];

pub(super) struct Hits {
    pub(super) found: Vec<(u64, CandidateKind)>,
    pub(super) zip_ends: BTreeMap<usize, Vec<usize>>,
    pub(super) zip_ends_dropped: u64,
    pub(super) total: u64,
    pub(super) not_examined: u64,
}

pub(super) fn accept(kind: CandidateKind, bytes: &[u8], offset: usize) -> bool {
    match kind {
        // The three-byte magic is weak; require the stream header and block magic.
        CandidateKind::Bzip2 => {
            bytes
                .get(offset + 3)
                .is_some_and(|level| (b'1'..=b'9').contains(level))
                && bytes.get(offset + 4..offset + 10) == Some(magic::BZIP2_BLOCK)
        }
        _ => true,
    }
}

pub(super) fn collect_hits(bytes: &[u8], run: &RunBudget) -> Result<Hits> {
    run.checkpoint()?;
    let per_signature = BOUNDS.max_hits_per_signature;
    let mut patterns: Vec<(Option<CandidateKind>, &[u8])> = SIGNATURES
        .iter()
        .map(|(kind, pattern)| (Some(*kind), *pattern))
        .collect();
    patterns.push((None, magic::ZIP_END));
    let scanned: Vec<_> = patterns
        .par_iter()
        .map(|(kind, pattern)| {
            const CHUNK_BYTES: usize = 4 * 1024 * 1024;
            let finder = memchr::memmem::Finder::new(pattern);
            let mut offsets = Vec::new();
            let mut total = 0u64;
            for start in (0..bytes.len()).step_by(CHUNK_BYTES) {
                run.checkpoint()?;
                let end = bytes
                    .len()
                    .min(start.saturating_add(CHUNK_BYTES + pattern.len() - 1));
                for hit in finder
                    .find_iter(&bytes[start..end])
                    .take_while(|&hit| hit < CHUNK_BYTES)
                {
                    let offset = start + hit;
                    if kind.is_some_and(|kind| !accept(kind, bytes, offset)) {
                        continue;
                    }
                    if kind.is_none() && zip_end_bounds(bytes, offset).is_none() {
                        continue;
                    }
                    total += 1;
                    if offsets.len() < per_signature {
                        offsets.push(offset as u64);
                    }
                }
            }
            Ok((*kind, offsets, total))
        })
        .collect::<Result<_>>()?;
    run.checkpoint()?;
    let mut hits = Hits {
        found: Vec::new(),
        zip_ends: BTreeMap::new(),
        zip_ends_dropped: 0,
        total: 0,
        not_examined: 0,
    };
    for (kind, offsets, total) in scanned {
        match kind {
            Some(kind) => {
                hits.total += total;
                hits.not_examined += total - offsets.len() as u64;
                hits.found
                    .extend(offsets.into_iter().map(|offset| (offset, kind)));
            }
            None => {
                hits.zip_ends_dropped = total - offsets.len() as u64;
                for offset in offsets {
                    if let Some((start, stop)) = zip_end_bounds(bytes, offset as usize) {
                        hits.zip_ends.entry(start).or_default().push(stop);
                    }
                }
            }
        }
    }
    hits.found.sort();
    Ok(hits)
}
