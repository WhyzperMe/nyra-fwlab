//! Evidence-based dispatch and strict recovery of standalone ZIP archives.
use crate::{
    archive::{ArchiveIssue, Exclusion, RecoveredFile, RecoveryMethod},
    bytes,
    central::{self, DirectoryAudit, LayoutError},
    magic,
    pihc::verify::decode_verified,
    squashfs, tar, uimage, zip,
};
use nyra_fw_core::{FwError, Limits, RecoverySummary, Result, budget::RunBudget, timings::Phase};
use rayon::prelude::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Pihc,
    Zip,
    SquashFs,
    ElfCandidate,
    UImage,
    Gzip,
    Tar,
    Unknown,
}

impl InputKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pihc => "hichip-pihc",
            Self::Zip => "zip",
            Self::SquashFs => "squashfs",
            Self::ElfCandidate => "elf-candidate",
            Self::UImage => "uimage",
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::Unknown => "unknown",
        }
    }
}

pub fn identify(raw: &[u8]) -> InputKind {
    // A two-byte gzip magic is enough here: a member with another method byte is
    // reported by the gzip reader as damaged, not silently treated as unknown.
    let starts = |signature: &[u8]| raw.starts_with(signature);
    if starts(magic::PIHC) {
        InputKind::Pihc
    } else if starts(magic::ZIP_LOCAL) || starts(magic::ZIP_END) {
        InputKind::Zip
    } else if starts(magic::GZIP) {
        InputKind::Gzip
    } else if starts(magic::SQUASHFS) {
        InputKind::SquashFs
    } else if starts(magic::ELF) {
        InputKind::ElfCandidate
    } else if starts(magic::UIMAGE) {
        InputKind::UImage
    } else if crate::tar::has_magic(raw) {
        InputKind::Tar
    } else {
        InputKind::Unknown
    }
}

pub fn structural_state(kind: InputKind, raw: &[u8], limits: &Limits) -> Result<&'static str> {
    limits.check_input(raw.len() as u64)?;
    Ok(match kind {
        InputKind::Pihc => {
            crate::pihc::PihcHeader::parse(raw)?;
            "header_bounds_validated"
        }
        InputKind::Zip | InputKind::Tar => {
            inspect_archive(kind, raw, &RunBudget::new(limits.clone(), None))?.structural_state()
        }
        InputKind::SquashFs if squashfs::inspect(raw).is_some() => "superblock_validated",
        InputKind::ElfCandidate if crate::candidates::elf_extent(raw).is_ok() => {
            "elf_header_tables_and_extent_validated"
        }
        InputKind::UImage if uimage::inspect(raw).is_some() => "header_and_payload_crc_validated",
        InputKind::Unknown => "unrecognized",
        _ => "magic_only",
    })
}

#[derive(Debug)]
pub struct ZipRecovery {
    pub directory: DirectoryAudit,
    pub files: Vec<RecoveredFile>,
    pub summary: RecoverySummary,
    pub failed_names: Vec<String>,
}

pub struct ZipIndex<'a> {
    raw: &'a [u8],
    run: &'a RunBudget,
    entries: Vec<zip::LocalEntry>,
    stats: zip::ScanStats,
}

/// Proof that the central and local records of a classic ZIP agree. It says nothing
/// about member encodings, names or payload checksums.
#[derive(Debug, Clone)]
pub struct ZipStructure {
    /// Offsets of the local headers relative to the archive start, ascending.
    pub member_offsets: Vec<usize>,
}

/// Why no classic ZIP structure could be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipStructureError {
    /// A count, size or offset needs ZIP64 records, which this build does not read.
    Zip64,
    /// The records are absent or disagree.
    Invalid,
}

/// Check a standalone ZIP's end, central and local records against each other, without
/// judging member encodings, paths or node types. [`inspect_archive`] adds those.
pub fn zip_structure(
    raw: &[u8],
    limits: &Limits,
) -> std::result::Result<ZipStructure, ZipStructureError> {
    if limits.check_input(raw.len() as u64).is_err() {
        return Err(ZipStructureError::Invalid);
    }
    let (local, layout) = central::standalone_layout(raw, limits).map_err(|error| match error {
        LayoutError::Zip64 => ZipStructureError::Zip64,
        LayoutError::Invalid => ZipStructureError::Invalid,
    })?;
    match zip::scan_indexed(local, limits, &layout, zip::Admission::Structure) {
        Ok((entries, _, issues)) if issues.is_empty() && entries.len() == layout.len() => {
            Ok(ZipStructure {
                member_offsets: layout.iter().map(|entry| entry.offset).collect(),
            })
        }
        // Streamed ZIP64 members announce themselves with marker sizes in the local header.
        _ if layout.iter().any(|entry| {
            [18, 22]
                .into_iter()
                .any(|at| bytes::le_u32(local, entry.offset + at) == Some(u32::MAX))
        }) =>
        {
            Err(ZipStructureError::Zip64)
        }
        _ => Err(ZipStructureError::Invalid),
    }
}

fn zip_index<'a>(raw: &'a [u8], run: &'a RunBudget) -> Result<ZipIndex<'a>> {
    let limits = &run.limits;
    limits.check_input(raw.len() as u64)?;
    let zip64 =
        || FwError::Unsupported("ZIP64 records are outside the supported ZIP subset".into());
    let (local, layout) = central::standalone_layout(raw, limits).map_err(|error| match error {
        LayoutError::Zip64 => zip64(),
        LayoutError::Invalid => {
            FwError::Verification("ZIP central-directory bounds are invalid".into())
        }
    })?;
    let (entries, stats, issues) =
        zip::scan_indexed(local, limits, &layout, zip::Admission::Extractable)?;
    if !issues.is_empty() || entries.len() != layout.len() {
        // Damage and unsupported content are different findings. Re-check the records
        // without the extraction policy to tell which one this is.
        return Err(match zip_structure(raw, limits) {
            Ok(_) => FwError::Unsupported(
                "ZIP members use an encoding, path or node type outside the supported subset"
                    .into(),
            ),
            Err(ZipStructureError::Zip64) => zip64(),
            Err(ZipStructureError::Invalid) => FwError::Verification(
                "ZIP directory does not account for a safe set of local records".into(),
            ),
        });
    }
    Ok(ZipIndex {
        raw,
        run,
        entries,
        stats,
    })
}

pub enum ArchiveIndex<'a> {
    Zip(ZipIndex<'a>),
    Tar(TarIndex<'a>),
}

pub struct TarIndex<'a>(tar::Archive<'a>);

impl<'a> TarIndex<'a> {
    pub fn archive(&self) -> &tar::Archive<'a> {
        &self.0
    }
}

#[derive(Serialize)]
pub struct ArchiveFinding<'a> {
    schema_version: u32,
    source_sha256: &'a str,
    format: InputKind,
    structural_state: &'static str,
    archive_bytes: usize,
    regular_members: Vec<ArchiveMemberFinding<'a>>,
}

#[derive(Serialize)]
struct ArchiveMemberFinding<'a> {
    name: &'a str,
    header_offset: usize,
    payload_offset: usize,
    stored_bytes: usize,
    declared_decoded_bytes: usize,
    declared_payload_crc32: Option<u32>,
}

pub fn inspect_archive<'a>(
    kind: InputKind,
    raw: &'a [u8],
    run: &'a RunBudget,
) -> Result<ArchiveIndex<'a>> {
    run.checkpoint()?;
    run.measure(Phase::ArchiveIndex, || match kind {
        InputKind::Zip => zip_index(raw, run).map(ArchiveIndex::Zip),
        InputKind::Tar => tar::index(raw, run).map(|archive| ArchiveIndex::Tar(TarIndex(archive))),
        _ => Err(FwError::Unsupported(
            "standalone ZIP or USTAR required".into(),
        )),
    })
}

impl ArchiveIndex<'_> {
    pub fn structural_state(&self) -> &'static str {
        match self {
            Self::Zip(_) => "central_and_local_metadata_validated",
            Self::Tar(_) => "tar_headers_and_member_bounds_validated",
        }
    }

    /// Structural evidence only. Declared ZIP CRCs are checked during recovery.
    pub fn finding<'a>(&'a self, source_sha256: &'a str) -> ArchiveFinding<'a> {
        let (format, archive_bytes, regular_members) = match self {
            Self::Zip(zip) => (
                InputKind::Zip,
                zip.raw.len(),
                zip.entries
                    .iter()
                    .filter(|entry| !entry.name.ends_with('/'))
                    .map(|entry| ArchiveMemberFinding {
                        name: &entry.name,
                        header_offset: entry.header_offset,
                        payload_offset: entry.data_offset,
                        stored_bytes: entry.compressed_size,
                        declared_decoded_bytes: entry.uncompressed_size,
                        declared_payload_crc32: Some(entry.crc32),
                    })
                    .collect(),
            ),
            Self::Tar(TarIndex(tar)) => (
                InputKind::Tar,
                tar.end,
                tar.members
                    .iter()
                    .map(|entry| ArchiveMemberFinding {
                        name: &entry.name,
                        header_offset: entry.header_offset(),
                        payload_offset: entry.offset,
                        stored_bytes: entry.bytes.len(),
                        declared_decoded_bytes: entry.bytes.len(),
                        declared_payload_crc32: None,
                    })
                    .collect(),
            ),
        };
        ArchiveFinding {
            schema_version: 1,
            source_sha256,
            format,
            structural_state: self.structural_state(),
            archive_bytes,
            regular_members,
        }
    }
}

pub fn recover_zip(raw: &[u8], limits: &Limits, require_all: bool) -> Result<ZipRecovery> {
    recover_zip_budgeted(raw, &RunBudget::new(limits.clone(), None), require_all)
}

pub fn recover_zip_budgeted(raw: &[u8], run: &RunBudget, require_all: bool) -> Result<ZipRecovery> {
    recover_zip_indexed(raw, run, require_all).map(|(result, _)| result)
}

pub fn recover_zip_indexed(
    raw: &[u8],
    run: &RunBudget,
    require_all: bool,
) -> Result<(ZipRecovery, Vec<ArchiveIssue>)> {
    run.checkpoint()?;
    zip_index(raw, run)?.recover(require_all)
}

impl ZipIndex<'_> {
    pub fn recover(&self, require_all: bool) -> Result<(ZipRecovery, Vec<ArchiveIssue>)> {
        let Self {
            raw,
            run,
            entries,
            stats,
        } = self;
        run.checkpoint()?;
        let limits = &run.limits;
        let mut issues = Vec::new();
        let total = entries
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(e.uncompressed_size as u64))
            .ok_or_else(|| FwError::Limit("ZIP declared output size overflow".into()))?;
        limits.check_total(total)?;
        let mut decoded = Vec::with_capacity(entries.len());
        run.batches(
            entries,
            |entry| entry.uncompressed_size as u64 + 1024,
            |batch| {
                let output: Vec<_> = batch
                    .par_iter()
                    .map(|e| {
                        decode_verified(
                            &raw[e.data_offset..e.data_offset + e.compressed_size],
                            e,
                            limits,
                        )
                    })
                    .collect();
                decoded.extend(output);
                Ok(())
            },
        )?;
        let mut files = Vec::new();
        let mut failed_names = Vec::new();
        for (entry, bytes) in entries.iter().zip(decoded) {
            let Some(bytes) = bytes else {
                issues.push(ArchiveIssue {
                    header_offset: entry.header_offset as u64,
                    reason: Exclusion::ContentVerificationFailed,
                });
                failed_names.push(entry.name.clone());
                continue;
            };
            if !entry.name.ends_with('/') {
                files.push(RecoveredFile::from_entry(
                    entry,
                    bytes,
                    RecoveryMethod::Original,
                    0,
                )?);
            }
        }
        if require_all && !failed_names.is_empty() {
            return Err(FwError::Verification(format!(
                "{} ZIP entries failed CRC or decompression",
                failed_names.len()
            )));
        }
        let summary = RecoverySummary {
            signatures_seen: stats.signatures,
            directory_entries: stats.directories,
            eligible_entries: stats.eligible,
            original_crc_ok: files.len(),
            failed_entries: failed_names.len(),
            bytes_recovered: files.iter().map(|f| f.bytes.len() as u64).sum(),
            ..RecoverySummary::default()
        };
        Ok((
            ZipRecovery {
                directory: central::verified_directory(entries.len()),
                files,
                summary,
                failed_names,
            },
            issues,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/central-valid.zip");
    const ZIP_BZIP2: &[u8] =
        include_bytes!("../../../tests/fixtures/synthetic/zip-bzip2-member.zip");
    const ZIP_ZIP64: &[u8] =
        include_bytes!("../../../tests/fixtures/synthetic/zip-zip64-member.zip");
    const TAR_REPEATED: &[u8] =
        include_bytes!("../../../tests/fixtures/synthetic/tar-repeated-members.tar");

    fn refusal(kind: InputKind, raw: &[u8]) -> FwError {
        match inspect_archive(kind, raw, &RunBudget::new(Limits::default(), None)) {
            Ok(_) => panic!("archive was accepted"),
            Err(error) => error,
        }
    }

    #[test]
    fn unsupported_content_is_told_apart_from_damage() {
        // Valid archives that this build cannot extract are unsupported, never "damaged".
        assert!(matches!(
            refusal(InputKind::Zip, ZIP_BZIP2),
            FwError::Unsupported(_)
        ));
        assert!(matches!(
            refusal(InputKind::Zip, ZIP_ZIP64),
            FwError::Unsupported(_)
        ));
        assert!(matches!(
            refusal(InputKind::Tar, TAR_REPEATED),
            FwError::Unsupported(_)
        ));
        // A broken record is damage.
        let mut damaged = ZIP.to_vec();
        let at = damaged.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        damaged[at + 42..at + 46].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            refusal(InputKind::Zip, &damaged),
            FwError::Verification(_)
        ));
    }

    #[test]
    fn zip_structure_is_judged_without_the_extraction_policy() {
        let limits = Limits::default();
        assert_eq!(
            zip_structure(ZIP_BZIP2, &limits).unwrap().member_offsets,
            [0]
        );
        assert_eq!(
            zip_structure(ZIP_ZIP64, &limits).unwrap_err(),
            ZipStructureError::Zip64
        );
        assert_eq!(
            zip_structure(&ZIP[..ZIP.len() - 1], &limits).unwrap_err(),
            ZipStructureError::Invalid
        );
    }

    #[test]
    fn every_proper_prefix_of_fixture_is_rejected() {
        for len in 0..ZIP.len() {
            assert!(
                recover_zip(&ZIP[..len], &Limits::default(), false).is_err(),
                "prefix {len}"
            );
        }
        assert_eq!(
            recover_zip(ZIP, &Limits::default(), true)
                .unwrap()
                .files
                .len(),
            1
        );
    }

    #[test]
    fn comments_are_outside_the_local_scan_and_crc_failures_are_explicit() {
        let limits = Limits::default();
        let mut archive = ZIP.to_vec();
        let size = archive.len();
        let comment = b"PK\x03\x04\0\0";
        archive[size - 2..size].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        archive.extend_from_slice(comment);
        let recovered = recover_zip(&archive, &limits, true).unwrap();
        archive[recovered.files[0].data_offset as usize] ^= 0x40;
        assert!(recover_zip(&archive, &limits, true).is_err());
        let partial = recover_zip(&archive, &limits, false).unwrap();
        assert!(partial.files.is_empty());
        assert_eq!(partial.summary.failed_entries, 1);
    }

    #[test]
    fn rejects_unix_symlink_and_respects_aggregate_budget() {
        let mut archive = ZIP.to_vec();
        let central = archive
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        archive[central + 5] = 3;
        archive[central + 38..central + 42].copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
        assert!(recover_zip(&archive, &Limits::default(), false).is_err());
        let limits = Limits {
            max_total_output_bytes: 0,
            ..Limits::default()
        };
        assert!(matches!(
            recover_zip(ZIP, &limits, false),
            Err(FwError::Limit(_))
        ));
    }

    #[test]
    fn classic_zip_checks_signed_and_unsigned_streaming_descriptors() {
        let limits = Limits::default();
        let original = recover_zip(ZIP, &limits, true).unwrap();
        let file = &original.files[0];
        let central = file.data_offset as usize + file.compressed_size as usize;
        let crc = crate::bytes::le_u32(ZIP, 14).unwrap();
        for signature in [false, true] {
            let mut archive = ZIP.to_vec();
            let mut descriptor = Vec::new();
            if signature {
                descriptor.extend_from_slice(magic::ZIP_DESCRIPTOR);
            }
            for value in [crc, file.compressed_size as u32, file.bytes.len() as u32] {
                descriptor.extend_from_slice(&value.to_le_bytes());
            }
            archive[6] |= 8;
            archive[14..26].fill(0);
            archive[central + 8] |= 8;
            archive.splice(central..central, descriptor.iter().copied());
            let eocd = archive.len() - 22;
            archive[eocd + 16..eocd + 20]
                .copy_from_slice(&((central + descriptor.len()) as u32).to_le_bytes());
            let recovered = recover_zip(&archive, &limits, true).unwrap();
            assert_eq!(recovered.files[0].bytes, file.bytes);
            assert_eq!(recovered.files[0].data_offset, file.data_offset);
            archive[central + descriptor.len() - 1] ^= 1;
            assert!(recover_zip(&archive, &limits, false).is_err());
        }
    }
}
