//! Turn a recovered or preserved input into the artifacts and evidence known before
//! any analysis report is written.
use crate::{output::write_new, source_map};
use nyra_fw_core::{Artifact, Evidence, FwError, RecoverySummary, Result, budget::RunBudget};
use nyra_fw_formats::{
    archive::{ArchiveReport, RecoveredFile},
    candidates::{self, CandidateKind},
    central,
    input::{self, InputKind},
    pihc::{self, PihcHeader, RecoveryResult},
    squashfs,
};
use std::path::Path;

pub(crate) enum RecoveredInput<'a> {
    Archive(RecoveredArchive<'a>),
    Gzip(&'a [u8]),
    Tar(&'a nyra_fw_formats::tar::Archive<'a>),
    Preserved { kind: InputKind, mode: Preservation },
}

#[derive(Clone, Copy)]
pub(crate) enum Preservation {
    Validated,
    Fallback(&'static str),
    Selected(u32),
}

pub(crate) struct RecoveredArchive<'a> {
    pub(crate) pihc_header: Option<&'a PihcHeader>,
    pub(crate) crypto_profile: Option<String>,
    pub(crate) files: &'a [RecoveredFile],
    pub(crate) summary: &'a RecoverySummary,
    pub(crate) failed: &'a [String],
    pub(crate) warnings: &'a [String],
    pub(crate) report: ArchiveReport,
}

impl<'a> RecoveredArchive<'a> {
    pub(crate) fn pihc(result: &'a RecoveryResult, report: ArchiveReport) -> Self {
        Self {
            pihc_header: Some(&result.header),
            crypto_profile: result.selected_variant.map(|v| v.label()),
            files: &result.files,
            summary: &result.summary,
            failed: &result.failed_names,
            warnings: &result.warnings,
            report,
        }
    }
}

/// What staging an input produced: the evidence and artifacts that are known
/// before any analysis stage runs.
pub(crate) struct Staged<'a> {
    pub(crate) detected: String,
    pub(crate) report: ArchiveReport,
    pub(crate) members: &'a [RecoveredFile],
    pub(crate) failed: &'a [String],
    pub(crate) summary: RecoverySummary,
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) warnings: Vec<String>,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) archive_offset: u64,
    pub(crate) crypto_profile: Option<String>,
    pub(crate) filesystem_image: Option<(String, &'a [u8])>,
    pub(crate) standalone_elf: Option<(String, &'a [u8])>,
    pub(crate) gzip_payload: Option<&'a [u8]>,
    pub(crate) structural_failure: Option<&'static str>,
    pub(crate) candidates: Option<candidates::CandidateReport>,
    pub(crate) candidate_selection: Option<source_map::CandidateSelection>,
}

impl<'a> Staged<'a> {
    fn new(
        raw: &[u8],
        report: ArchiveReport,
        members: &'a [RecoveredFile],
        failed: &'a [String],
    ) -> Self {
        Self {
            detected: input::identify(raw).label().to_owned(),
            report,
            members,
            failed,
            summary: RecoverySummary::default(),
            artifacts: Vec::new(),
            warnings: Vec::new(),
            evidence: Vec::new(),
            archive_offset: 0,
            crypto_profile: None,
            filesystem_image: None,
            standalone_elf: None,
            gzip_payload: None,
            structural_failure: None,
            candidates: None,
            candidate_selection: None,
        }
    }
}

pub(crate) fn no_directory() -> ArchiveReport {
    ArchiveReport {
        directory: central::not_applicable(),
        issues: Vec::new(),
    }
}

pub(crate) fn stage_tar<'a>(
    root: &Path,
    raw: &'a [u8],
    input_sha: &str,
    archive: &nyra_fw_formats::tar::Archive<'a>,
    run: &RunBudget,
) -> Result<Staged<'a>> {
    let mut staged = Staged::new(raw, no_directory(), &[], &[]);
    let mut filesystems = Vec::new();
    for member in &archive.members {
        run.checkpoint()?;
        let artifact = source_map::tar_member(member, input_sha);
        write_new(root, &artifact.path, member.bytes)?;
        if artifact.kind == nyra_fw_core::ArtifactKind::SquashFsImage {
            filesystems.push((artifact.path.clone(), member.bytes));
        }
        staged.artifacts.push(artifact);
    }
    if let [filesystem] = filesystems.as_slice() {
        staged.filesystem_image = Some(filesystem.clone());
    } else if filesystems.len() > 1 {
        staged
            .warnings
            .push("Multiple TAR members contain SquashFS. Select an image for extraction.".into());
    }
    staged.warnings.push("TAR header checksums cover metadata. Copied members have source ranges and SHA-256 but lack independent payload checksums.".into());
    if source_map::has_non_fill_tail(raw, archive.end) {
        staged
            .warnings
            .push("Data after the first TAR end marker remains in the original input.".into());
    }
    staged.candidates = Some(candidates::scan(raw, input_sha, run)?);
    Ok(staged)
}

/// PIHC and classic ZIP: the members were recovered by the format reader.
pub(crate) fn stage_archive<'a>(
    root: &Path,
    raw: &'a [u8],
    input_sha: &str,
    archive: RecoveredArchive<'a>,
) -> Result<Staged<'a>> {
    let mut staged = Staged::new(raw, archive.report, archive.files, archive.failed);
    staged.summary.clone_from(archive.summary);
    staged.warnings.extend_from_slice(archive.warnings);
    staged.crypto_profile = archive.crypto_profile;
    let Some(expected_header) = archive.pihc_header else {
        staged.evidence.push(Evidence::derived(
            "ZIP archive",
            "central and local records",
            "metadata cross-checked against contiguous local records",
        ));
        if !archive.failed.is_empty() {
            staged
                .warnings
                .push("Entries that failed verification are absent from recovered output.".into());
        }
        return Ok(staged);
    };
    let header = PihcHeader::parse(raw)?;
    if &header != expected_header {
        return Err(FwError::Verification(
            "PIHC result belongs to a different input".into(),
        ));
    }
    staged.archive_offset = header.archive_offset as u64;
    let header_bytes = &raw[..pihc::header::HEADER_SIZE];
    let artifact = source_map::Carve::PihcHeader.artifact(
        header_bytes,
        input_sha,
        (0, header_bytes.len() as u64),
    );
    write_new(root, &artifact.path, header_bytes)?;
    staged.artifacts.push(artifact);
    let pre = header.pre_archive(raw);
    let artifact = source_map::Carve::PihcPreArchive {
        squashfs: header.pre_archive_is_squashfs,
    }
    .artifact(
        pre,
        input_sha,
        (header_bytes.len() as u64, pre.len() as u64),
    );
    write_new(root, &artifact.path, pre)?;
    let pre_path = artifact.path.clone();
    staged.artifacts.push(artifact);
    if let Some(s) = squashfs::inspect(pre) {
        staged.filesystem_image = Some((pre_path, pre));
        staged.evidence.push(Evidence::derived(
            format!(
                "SquashFS 4.0, {} inodes, {} bytes used",
                s.inodes, s.bytes_used
            ),
            "pre-archive superblock",
            "static header parse",
        ));
    } else if header.pre_archive_is_squashfs {
        staged
            .warnings
            .push("SquashFS magic found with an invalid superblock. Raw segment preserved.".into());
    }
    staged.evidence.push(Evidence::derived(
        "PIHC update package",
        "input header",
        "PIHC magic and validated archive offset",
    ));
    Ok(staged)
}

/// One verified gzip member: the decoded payload is the only artifact.
pub(crate) fn stage_gzip<'a>(
    root: &Path,
    raw: &'a [u8],
    input_sha: &str,
    payload: &'a [u8],
) -> Result<Staged<'a>> {
    let mut staged = Staged::new(raw, no_directory(), &[], &[]);
    staged.gzip_payload = Some(payload);
    let artifact = source_map::Carve::Gzip.artifact(payload, input_sha, (0, raw.len() as u64));
    write_new(root, &artifact.path, payload)?;
    if squashfs::inspect(payload).is_some() {
        staged.filesystem_image = Some((artifact.path.clone(), payload));
    }
    if payload.starts_with(nyra_fw_formats::magic::ELF) {
        staged.standalone_elf = Some((source_map::GZIP_PATH.to_owned(), payload));
    }
    staged.artifacts.push(artifact);
    staged.evidence.push(Evidence::derived(
        "gzip payload",
        "gzip member",
        "decoded with validated CRC32 and ISIZE trailer",
    ));
    Ok(staged)
}

/// Input kept as bytes. A rejected input gets the bounded candidate scan and the
/// carves of validated, conflict-free candidates; a recognized one gets its
/// single carve, if its format defines one.
pub(crate) fn stage_preserved<'a>(
    root: &Path,
    raw: &'a [u8],
    input_sha: &str,
    original_path: &str,
    run: &RunBudget,
    kind: InputKind,
    mode: Preservation,
) -> Result<Staged<'a>> {
    let mut staged = Staged::new(raw, no_directory(), &[], &[]);
    let mut inspected_end = None;
    if !matches!(mode, Preservation::Validated) {
        let selection = match mode {
            Preservation::Selected(id) => {
                staged.warnings.push("Original bytes preserved. Only the explicitly selected embedded candidate was carved.".into());
                Some(source_map::CandidateSelection {
                    schema_version: 1,
                    source_sha256: input_sha.into(),
                    id,
                })
            }
            Preservation::Fallback(reason) => {
                staged.structural_failure = Some(reason);
                staged
                    .warnings
                    .push("Input did not pass format validation. Original bytes preserved.".into());
                None
            }
            Preservation::Validated => None,
        };
        staged.detected = nyra_fw_core::format_label(&staged.detected, true);
        let scanned = candidates::scan(raw, input_sha, run)?;
        let carves = if let Some(selection) = &selection {
            vec![source_map::selected_carve(
                &scanned,
                raw,
                selection,
                run.limits.max_total_output_bytes,
            )?]
        } else {
            source_map::candidate_carves(&scanned, raw, run.limits.max_total_output_bytes)
        };
        let carved = carves.len();
        let mut squashfs_images = Vec::new();
        for (candidate, bytes) in carves {
            run.checkpoint()?;
            let artifact = source_map::candidate_artifact(candidate, bytes, input_sha);
            write_new(root, &artifact.path, bytes)?;
            if candidate.kind == CandidateKind::SquashFs {
                squashfs_images.push((artifact.path.clone(), bytes));
            }
            if selection.is_some() && candidate.kind == CandidateKind::Elf {
                staged.standalone_elf = Some((artifact.path.clone(), bytes));
            }
            staged.artifacts.push(artifact);
        }
        if let [image] = squashfs_images.as_slice() {
            staged.filesystem_image = Some(image.clone());
        } else if squashfs_images.len() > 1 {
            staged.warnings.push("Multiple SquashFS candidates were carved. Automatic extraction requires a unique image.".into());
        }
        staged.warnings.push(format!(
            "Candidate scan outcome {:?}: {} structure(s) validated, {carved} carved. See analysis/workspace/candidates.json.",
            scanned.outcome,
            scanned.top_level_validated()
        ));
        staged.candidates = Some(scanned);
        staged.candidate_selection = selection;
    } else if kind == InputKind::SquashFs {
        staged.filesystem_image = Some((original_path.to_owned(), raw));
        inspected_end = squashfs::inspect(raw).map(|header| header.bytes_used as usize);
    } else if kind == InputKind::UImage {
        let image = nyra_fw_formats::uimage::inspect(raw)
            .ok_or_else(|| FwError::Verification("uImage header or payload CRC mismatch".into()))?;
        let start = nyra_fw_formats::uimage::HEADER_SIZE;
        let end = start + image.payload_bytes as usize;
        inspected_end = Some(end);
        let payload = &raw[start..end];
        let artifact = source_map::Carve::UImage.artifact(
            payload,
            input_sha,
            (start as u64, payload.len() as u64),
        );
        write_new(root, &artifact.path, payload)?;
        if image.compression == 0 && squashfs::inspect(payload).is_some() {
            staged.filesystem_image = Some((artifact.path.clone(), payload));
        }
        staged.artifacts.push(artifact);
    }
    if kind == InputKind::ElfCandidate && matches!(mode, Preservation::Validated) {
        staged.standalone_elf = Some((original_path.to_owned(), raw));
    }
    if inspected_end.is_some_and(|end| source_map::has_non_fill_tail(raw, end)) {
        staged.candidates = Some(candidates::scan(raw, input_sha, run)?);
    }
    Ok(staged)
}
