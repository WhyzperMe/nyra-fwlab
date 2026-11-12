//! Explicit reference from recovery members back to original byte offsets.
use nyra_fw_core::{Artifact, ArtifactKind, Verification};
use nyra_fw_formats::{
    archive::{RecoveredFile, RecoveryMethod},
    candidates::{Candidate, CandidateKind, Status},
};

pub(crate) const GZIP_PATH: &str = "recovered/images/gzip-payload.bin";

pub(crate) fn has_non_fill_tail(raw: &[u8], consumed: usize) -> bool {
    raw.get(consumed..)
        .is_some_and(|tail| tail.iter().any(|&byte| !matches!(byte, 0 | 255)))
}

pub(crate) fn tar_member(member: &nyra_fw_formats::tar::Member<'_>, source: &str) -> Artifact {
    Artifact {
        path: format!("recovered/unverified/tar/{}", member.name),
        kind: if nyra_fw_formats::squashfs::inspect(member.bytes).is_some() {
            ArtifactKind::SquashFsImage
        } else {
            ArtifactKind::Other
        },
        size: member.bytes.len() as u64,
        sha256: nyra_fw_core::sha256_hex(member.bytes),
        verification: Verification::Unverified,
        source_start: member.offset as u64,
        source_length: member.bytes.len() as u64,
        transformation: "raw-carve:tar-member".into(),
        parent_sha256: source.into(),
    }
}

pub(crate) enum Carve {
    PihcHeader,
    PihcPreArchive { squashfs: bool },
    UImage,
    Gzip,
}

impl Carve {
    pub(crate) fn artifact(self, bytes: &[u8], source: &str, range: (u64, u64)) -> Artifact {
        use ArtifactKind::{FirmwareImage, Other, SquashFsImage};
        use Verification::{HeaderValidated, OriginalCrc32, Unverified};
        let (path, kind, verification, transformation) = match self {
            Self::PihcHeader => (
                "recovered/containers/pihc_header.bin",
                Other,
                HeaderValidated,
                "raw-carve:pihc-header",
            ),
            Self::PihcPreArchive { squashfs: true } => (
                "recovered/images/pre_archive.squashfs",
                SquashFsImage,
                Unverified,
                "raw-carve:pre-archive",
            ),
            Self::PihcPreArchive { squashfs: false } => (
                "recovered/images/pre_archive.bin",
                FirmwareImage,
                Unverified,
                "raw-carve:pre-archive",
            ),
            Self::UImage => (
                "recovered/images/uimage-payload.bin",
                FirmwareImage,
                OriginalCrc32,
                "raw-carve:uboot-legacy-payload",
            ),
            Self::Gzip => (
                GZIP_PATH,
                FirmwareImage,
                OriginalCrc32,
                "gzip:single-member",
            ),
        };
        Artifact {
            path: path.into(),
            kind,
            size: bytes.len() as u64,
            sha256: nyra_fw_core::sha256_hex(bytes),
            verification,
            source_start: range.0,
            source_length: range.1,
            transformation: transformation.into(),
            parent_sha256: source.into(),
        }
    }
}

pub fn recovered_artifact(
    file: &RecoveredFile,
    source_sha256: &str,
    variant: Option<&str>,
) -> Artifact {
    let method = match file.method {
        RecoveryMethod::Original => (
            Verification::OriginalCrc32,
            "zip-stored-or-deflate".to_owned(),
        ),
        RecoveryMethod::Decrypted => (
            Verification::RecoveredCrc32,
            variant.unwrap_or("unknown-hichip-variant").to_owned(),
        ),
    };
    Artifact {
        path: format!("recovered/update/{}", file.name),
        kind: ArtifactKind::ArchiveMember,
        size: file.bytes.len() as u64,
        sha256: nyra_fw_core::sha256_hex(&file.bytes),
        verification: method.0,
        source_start: file.data_offset,
        source_length: file.compressed_size,
        transformation: method.1,
        parent_sha256: source_sha256.to_owned(),
    }
}

/// Upper bounds for raw carves of unrecognized input; the byte total also obeys
/// `Limits::max_total_output_bytes`.
pub(crate) const MAX_CANDIDATE_CARVES: usize = 64;

/// Raw carve of one validated, conflict-free top-level candidate. The bytes are
/// the exact source range. The payload checksum, when the format has one, was
/// verified on those bytes; other kinds only passed their structure check.
pub(crate) fn candidate_artifact(
    candidate: &Candidate,
    bytes: &[u8],
    source_sha256: &str,
) -> Artifact {
    let label = candidate.kind.label();
    Artifact {
        path: candidate_path(candidate),
        kind: if candidate.kind == CandidateKind::SquashFs {
            ArtifactKind::SquashFsImage
        } else {
            ArtifactKind::FirmwareImage
        },
        size: bytes.len() as u64,
        sha256: nyra_fw_core::sha256_hex(bytes),
        verification: if candidate.status == Status::PayloadVerified {
            Verification::OriginalCrc32
        } else {
            Verification::HeaderValidated
        },
        source_start: candidate.offset,
        source_length: bytes.len() as u64,
        transformation: format!("raw-carve:candidate-{label}"),
        parent_sha256: source_sha256.to_owned(),
    }
}

pub(crate) fn candidate_path(candidate: &Candidate) -> String {
    format!(
        "recovered/images/candidates/{:04}-{}-0x{:08x}.bin",
        candidate.id,
        candidate.kind.label(),
        candidate.offset
    )
}

/// Select the carvable candidates inside the carve bounds, in report order, and
/// pair each with its exact source bytes. Identical selection in publication and
/// replay keeps the two derivations comparable.
pub(crate) fn candidate_carves<'r, 'b>(
    report: &'r nyra_fw_formats::candidates::CandidateReport,
    raw: &'b [u8],
    max_total: u64,
) -> Vec<(&'r Candidate, &'b [u8])> {
    let mut total = 0u64;
    nyra_fw_formats::candidates::carvable(report)
        .filter_map(|candidate| {
            Some((
                candidate,
                candidate_bytes(candidate, raw, &report.source_sha256)?,
            ))
        })
        .take(MAX_CANDIDATE_CARVES)
        .take_while(|(_, bytes)| {
            total = total.saturating_add(bytes.len() as u64);
            total <= max_total
        })
        .collect()
}

pub(crate) const SELECTION_PATH: &str = "analysis/workspace/candidate-selection.json";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateSelection {
    pub(crate) schema_version: u32,
    pub(crate) source_sha256: String,
    pub(crate) id: u32,
}

pub(crate) fn selected_carve<'r, 'b>(
    report: &'r nyra_fw_formats::candidates::CandidateReport,
    raw: &'b [u8],
    selection: &CandidateSelection,
    max_total: u64,
) -> nyra_fw_core::Result<(&'r Candidate, &'b [u8])> {
    use nyra_fw_core::FwError;
    if selection.schema_version != 1 || selection.source_sha256 != report.source_sha256 {
        return Err(FwError::Verification(
            "candidate selection source or schema mismatch".into(),
        ));
    }
    if report.budget_exhausted {
        return Err(FwError::Limit(
            "candidate selection requires a scan within its budgets".into(),
        ));
    }
    let selected = nyra_fw_formats::candidates::carvable(report)
        .find(|candidate| candidate.id == selection.id)
        .and_then(|candidate| {
            Some((
                candidate,
                candidate_bytes(candidate, raw, &report.source_sha256)?,
            ))
        })
        .ok_or_else(|| {
            FwError::Config(format!(
                "candidate #{} is not a validated, conflict-free top-level carve",
                selection.id,
            ))
        })?;
    if selected.1.len() as u64 > max_total {
        return Err(FwError::Limit(
            "selected carve exceeds the output byte budget".into(),
        ));
    }
    Ok(selected)
}

fn candidate_bytes<'b>(candidate: &Candidate, raw: &'b [u8], sha256: &str) -> Option<&'b [u8]> {
    use nyra_fw_core::source::{ByteSource, Original};
    candidate
        .original_range(ByteSource::new(raw, Original { sha256 }))
        .map(|range| range.bytes())
}
