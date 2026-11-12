//! Parallel, bounded, independently CRC-verified PIHC member recovery.
//! The signature scan is conservative, so successful members do not prove
//! full archive completeness or that the package is a flashable image.
use super::{
    crypto::{CryptoVariant, KeyMode, restore_payload},
    header::PihcHeader,
    verify::decode_verified,
};
use crate::{
    archive::{ArchiveIssue, ArchiveReport, Exclusion},
    zip::{LocalEntry, ScanStats},
};
use nyra_fw_core::{FwError, Limits, RecoverySummary, Result, budget::RunBudget};
use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    pub limits: Limits,
    pub key_mode: KeyMode,
    /// Fail rather than publish a partial recovery.
    pub require_all: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            key_mode: KeyMode::Known(CryptoVariant::PHASE01),
            require_all: true,
        }
    }
}

pub use crate::archive::{RecoveredFile, RecoveryMethod};

#[derive(Debug)]
pub struct RecoveryResult {
    pub header: PihcHeader,
    pub selected_variant: Option<CryptoVariant>,
    pub summary: RecoverySummary,
    pub files: Vec<RecoveredFile>,
    pub failed_names: Vec<String>,
    pub warnings: Vec<String>,
}

/// Outcome of probing the 48 AES variants against sample members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// One variant validated the most samples, or PHASE01 tied for the most.
    Selected(CryptoVariant, usize),
    /// Several variants validated the same number of samples and none is PHASE01.
    Ambiguous {
        variants: usize,
        hits: usize,
    },
    NoMatch,
}

/// Choose among scored variants. A tie that does not include the documented
/// PHASE01 variant stays ambiguous instead of falling to enumeration order.
pub(crate) fn select_variant(scores: &[(CryptoVariant, usize)]) -> Probe {
    let best = scores.iter().map(|(_, hits)| *hits).max().unwrap_or(0);
    if best == 0 {
        return Probe::NoMatch;
    }
    let tied: Vec<_> = scores.iter().filter(|(_, hits)| *hits == best).collect();
    if let Some((variant, _)) = tied.iter().find(|(v, _)| *v == CryptoVariant::PHASE01) {
        return Probe::Selected(*variant, best);
    }
    match tied.as_slice() {
        [(variant, _)] => Probe::Selected(*variant, best),
        _ => Probe::Ambiguous {
            variants: tied.len(),
            hits: best,
        },
    }
}

fn original(archive: &[u8], entry: &LocalEntry, limits: &Limits) -> Option<Vec<u8>> {
    let raw =
        archive.get(entry.data_offset..entry.data_offset.checked_add(entry.compressed_size)?)?;
    decode_verified(raw, entry, limits)
}

/// Probe only *preselected failed* files. Full CRC+length verification prevents
/// treating a plausible entropy or header match as successful decryption.
fn probe_failed(archive: &[u8], mut broken: Vec<&LocalEntry>, run: &RunBudget) -> Result<Probe> {
    let limits = &run.limits;
    let cost = |e: &LocalEntry| e.compressed_size.saturating_add(e.uncompressed_size);
    broken.sort_by_key(|e| (cost(e), e.header_offset));
    let mut budget = 16 * 1024 * 1024;
    let sample: Vec<_> = broken
        .into_iter()
        .take(12)
        .take_while(|e| {
            if cost(e) > budget {
                return false;
            }
            budget -= cost(e);
            true
        })
        .collect();
    if sample.is_empty() {
        return Ok(Probe::NoMatch);
    }
    let variants: Vec<_> = (0u8..48).collect();
    let mut scores = Vec::with_capacity(variants.len());
    let peak = sample.iter().map(|e| cost(e) as u64).max().unwrap_or(0);
    run.batches(
        &variants,
        |_| peak.saturating_add(1024),
        |batch| {
            let batch_scores: Vec<_> = batch
                .par_iter()
                .map(|&i| {
                    let variant = CryptoVariant {
                        phase: i / 3,
                        rotation: i % 3,
                    };
                    let hits = sample
                        .iter()
                        .filter(|e| {
                            if limits
                                .check_entry(e.compressed_size as u64, e.uncompressed_size as u64)
                                .is_err()
                            {
                                return false;
                            }
                            restore_payload(archive, e.data_offset, e.compressed_size, variant)
                                .ok()
                                .and_then(|payload| decode_verified(&payload, e, limits))
                                .is_some()
                        })
                        .count();
                    (variant, hits)
                })
                .collect();
            scores.extend(batch_scores);
            Ok(())
        },
    )?;
    // Several variants validating the same samples is possible only by accident
    // or by a sample that fits one block; do not pick one by enumeration order.
    Ok(select_variant(&scores))
}

pub fn recover(package: &[u8], options: &RecoveryOptions) -> Result<RecoveryResult> {
    recover_indexed(
        package,
        options,
        &RunBudget::new(options.limits.clone(), None),
    )
    .map(|(result, _)| result)
}

/// Recover members and audit the same local index used for decoding.
pub fn recover_indexed(
    package: &[u8],
    options: &RecoveryOptions,
    run: &RunBudget,
) -> Result<(RecoveryResult, ArchiveReport)> {
    run.checkpoint()?;
    let limits = &run.limits;
    limits.check_input(package.len() as u64)?;
    let header = PihcHeader::parse(package)?;
    let archive = header.archive(package);
    let (entries, scan_stats, mut issues) = crate::zip::scan(archive, limits)?;
    for issue in &mut issues {
        issue.header_offset += header.archive_offset as u64;
    }
    if entries.is_empty() {
        return Err(FwError::Invalid(
            "no eligible PIHC ZIP local headers".into(),
        ));
    }
    let expected_total = entries
        .iter()
        .try_fold(0u64, |sum, e| sum.checked_add(e.uncompressed_size as u64))
        .ok_or_else(|| FwError::Limit("sum of entry sizes overflowed".into()))?;
    limits.check_total(expected_total)?;

    let mut decoded = Vec::with_capacity(entries.len());
    run.batches(
        &entries,
        |entry| entry.uncompressed_size as u64 + 1024,
        |batch| {
            let outputs: Vec<_> = batch
                .par_iter()
                .map(|entry| {
                    original(archive, entry, limits).map(|bytes| (bytes, RecoveryMethod::Original))
                })
                .collect();
            decoded.extend(outputs);
            Ok(())
        },
    )?;
    let mut ambiguous = None;
    let (variant, hits) = match options.key_mode {
        KeyMode::Known(v) => (Some(v.validate()?), None),
        KeyMode::Probe => {
            let failed = entries
                .iter()
                .zip(&decoded)
                .filter_map(|(entry, output)| output.is_none().then_some(entry))
                .collect();
            match probe_failed(archive, failed, run)? {
                Probe::Selected(variant, hits) => (Some(variant), Some(hits)),
                Probe::Ambiguous { variants, hits } => {
                    ambiguous = Some((variants, hits));
                    (None, None)
                }
                Probe::NoMatch => (None, None),
            }
        }
    };
    let selected = variant;
    if let Some(variant) = selected {
        let mut remaining = decoded.as_mut_slice();
        run.batches(
            &entries,
            |entry| entry.compressed_size as u64 + entry.uncompressed_size as u64 + 1024,
            |batch| {
                let (outputs, rest) = std::mem::take(&mut remaining).split_at_mut(batch.len());
                remaining = rest;
                outputs
                    .par_iter_mut()
                    .zip(batch.par_iter())
                    .for_each(|(output, entry)| {
                        if output.is_none() {
                            *output = restore_payload(
                                archive,
                                entry.data_offset,
                                entry.compressed_size,
                                variant,
                            )
                            .ok()
                            .and_then(|payload| decode_verified(&payload, entry, limits))
                            .map(|bytes| (bytes, RecoveryMethod::Decrypted));
                        }
                    });
                Ok(())
            },
        )?;
    }

    let mut summary = summary_from_scan(scan_stats);
    let mut files = Vec::with_capacity(entries.len());
    let mut failed_names = Vec::new();
    let mut allocated = 0u64;
    for (entry, result) in entries.iter().zip(decoded) {
        match result {
            Some((bytes, method)) => {
                allocated += bytes.len() as u64;
                match method {
                    RecoveryMethod::Original => summary.original_crc_ok += 1,
                    RecoveryMethod::Decrypted => summary.recovered_crc_ok += 1,
                }
                files.push(RecoveredFile::from_entry(
                    entry,
                    bytes,
                    method,
                    header.archive_offset,
                )?);
            }
            None => {
                failed_names.push(entry.name.clone());
                issues.push(ArchiveIssue {
                    header_offset: (header.archive_offset + entry.header_offset) as u64,
                    reason: Exclusion::ContentVerificationFailed,
                });
            }
        }
    }
    summary.bytes_recovered = allocated;
    summary.failed_entries = failed_names.len();
    if options.require_all && !failed_names.is_empty() {
        return Err(FwError::Verification(format!(
            "{} / {} eligible files failed CRC recovery; first: {}",
            failed_names.len(),
            entries.len(),
            failed_names[0]
        )));
    }

    let mut warnings = vec!["CRC32 validates recovered ZIP members, not completeness, trustworthiness, or flashability of the full firmware.".to_owned()];
    if summary.unsupported_entries != 0 || summary.duplicate_names != 0 {
        warnings
            .push("Unsupported ZIP members or path collisions were excluded from recovery.".into());
    }
    if header.pre_archive_is_squashfs {
        warnings.push(
            "Pre-archive segment has SquashFS magic, not a verified Linux kernel image.".to_owned(),
        );
    } else {
        warnings.push("Pre-archive segment is unidentified; preserved unchanged.".to_owned());
    }
    if let Some(n) = hits {
        warnings.push(format!("AES variant selected by probing {n} CRC-confirmed sample member(s); profile not independently authenticated."));
    } else if let Some((variants, hits)) = ambiguous {
        warnings.push(format!(
            "AES variant is ambiguous: {variants} variants each validated {hits} sample member(s). None was selected; original CRC-valid members only."
        ));
    } else if options.key_mode == KeyMode::Probe {
        warnings.push(
            "No valid HiChip AES variant detected; original CRC-valid members only.".to_owned(),
        );
    }
    if !failed_names.is_empty() {
        warnings.push(format!(
            "{} eligible member(s) were not recovered and are absent from verified output",
            failed_names.len()
        ));
    }
    let directory = crate::central::audit(archive, &entries, limits);
    Ok((
        RecoveryResult {
            header,
            selected_variant: selected,
            summary,
            files,
            failed_names,
            warnings,
        },
        ArchiveReport { directory, issues },
    ))
}

fn summary_from_scan(s: ScanStats) -> RecoverySummary {
    RecoverySummary {
        signatures_seen: s.signatures,
        directory_entries: s.directories,
        eligible_entries: s.eligible,
        unsupported_entries: s.unsupported,
        duplicate_names: s.duplicate_names,
        ..RecoverySummary::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::safe_member_path;

    #[test]
    fn variant_ties_stay_ambiguous_unless_the_documented_variant_is_among_them() {
        let v = |phase, rotation| CryptoVariant { phase, rotation };
        assert_eq!(select_variant(&[]), Probe::NoMatch);
        assert_eq!(
            select_variant(&[(v(2, 1), 0), (v(3, 0), 0)]),
            Probe::NoMatch
        );
        assert_eq!(
            select_variant(&[(v(2, 1), 3), (v(3, 0), 1)]),
            Probe::Selected(v(2, 1), 3)
        );
        assert_eq!(
            select_variant(&[(v(2, 1), 2), (v(5, 2), 2)]),
            Probe::Ambiguous {
                variants: 2,
                hits: 2
            }
        );
        assert_eq!(
            select_variant(&[(v(2, 1), 2), (CryptoVariant::PHASE01, 2)]),
            Probe::Selected(CryptoVariant::PHASE01, 2)
        );
    }
    #[test]
    fn limits_are_nonzero_and_path_strict() {
        assert!(Limits::default().max_total_output_bytes > 0);
        assert!(!safe_member_path("/etc/shadow"));
    }
    #[test]
    fn invalid_variant_rejected() {
        assert!(
            CryptoVariant {
                phase: 16,
                rotation: 0
            }
            .validate()
            .is_err()
        );
    }
}

#[cfg(test)]
mod integration_fixture_tests {
    use super::*;
    use nyra_fw_core::sha256_hex;

    const SAMPLE: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic/pihc-phase01.pkg");
    #[test]
    fn recovers_encrypted_and_plain_member() {
        let result = recover(SAMPLE, &RecoveryOptions::default()).expect("synthetic package");
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.summary.recovered_crc_ok, 1);
        assert_eq!(result.summary.original_crc_ok, 1);
        assert_eq!(result.header.archive_offset, 640);
        let first = &result.files[0];
        assert_eq!(first.name, "mnt/mtd/ipc/test_motor.dat");
        assert_eq!(first.bytes.len(), 3100);
        let original: Vec<_> = (0..3100).map(|i| (i * 37 + 13) as u8).collect();
        assert_eq!(sha256_hex(&first.bytes), sha256_hex(&original));
        let second = &result.files[1];
        assert_eq!(second.name, "config/camera.ini");
        assert_eq!(second.bytes, b"[camera]\nmodel=synthetic\n");
    }

    #[test]
    fn auto_detects_variant_with_verified_crc() {
        let result = recover(
            SAMPLE,
            &RecoveryOptions {
                key_mode: KeyMode::Probe,
                ..RecoveryOptions::default()
            },
        )
        .expect("auto recovery");
        assert_eq!(result.selected_variant, Some(CryptoVariant::PHASE01));
    }

    #[test]
    fn corrupted_member_is_not_accepted() {
        let mut damaged = SAMPLE.to_vec();
        // Fault outside the AES-transformed block, within first member payload.
        damaged[640 + 300] ^= 0x7b;
        assert!(recover(&damaged, &RecoveryOptions::default()).is_err());
    }
}
