//! Bounded discovery of embedded container candidates in unknown or damaged input.
//!
//! Evidence has three separate tiers: a signature hit, a structurally validated
//! candidate and a candidate whose payload checksum was verified. Every candidate
//! is validated on its own bytes; a hit inside another candidate inherits nothing.
//! Overlapping validated candidates stay ambiguous. Reports contain only typed
//! fields and fixed labels, never strings copied from the firmware.
//!
//! The module is split by responsibility: `hits` finds signatures, `engine` validates
//! and relates candidates, `headers` holds the format-specific header checks and
//! `entropy` summarizes block statistics.
mod engine;
mod entropy;
mod headers;
mod hits;
#[cfg(test)]
mod tests;

use nyra_fw_core::source::{ByteSource, CheckedRange, DecodedGzip, Original};
use serde::{Deserialize, Serialize};

impl Candidate {
    /// Admit wire offsets only in the original input coordinate space.
    pub fn original_range<'a, 's>(
        &self,
        source: ByteSource<'a, Original<'s>>,
    ) -> Option<CheckedRange<'a, Original<'s>>> {
        if self.container.is_some() {
            return None;
        }
        source.range(self.offset, self.extent?)
    }

    /// Decoded offsets are valid only for the named gzip parent's payload.
    pub fn decoded_range<'a>(
        &self,
        bytes: &'a [u8],
        identity: DecodedGzip<'a>,
    ) -> Option<CheckedRange<'a, DecodedGzip<'a>>> {
        if self.container != Some(identity.candidate_id) {
            return None;
        }
        ByteSource::new(bytes, identity).range(self.offset, self.extent?)
    }
}

pub use engine::scan;
pub(crate) use headers::elf_extent;

pub const SCHEMA_VERSION: u32 = 2;

/// Hard bounds for one scan. They are part of the report so a reader can tell a
/// complete answer from one cut short by a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScanBounds {
    pub max_hits_per_signature: usize,
    pub max_validation_attempts: usize,
    pub max_decoded_bytes: u64,
    pub max_validation_bytes: u64,
    pub max_depth: u8,
    pub max_candidates: usize,
}

pub const BOUNDS: ScanBounds = ScanBounds {
    max_hits_per_signature: 4096,
    max_validation_attempts: 512,
    max_decoded_bytes: 128 * 1024 * 1024,
    max_validation_bytes: 512 * 1024 * 1024,
    max_depth: 2,
    max_candidates: 2048,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Pihc,
    Zip,
    Gzip,
    #[serde(rename = "squashfs")]
    SquashFs,
    #[serde(rename = "squashfs_big_endian")]
    SquashFsBigEndian,
    #[serde(rename = "uimage")]
    UImage,
    Elf,
    Fdt,
    Ubi,
    Xz,
    Bzip2,
    Zstd,
}

impl CandidateKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pihc => "pihc",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::SquashFs => "squashfs",
            Self::SquashFsBigEndian => "squashfs-big-endian",
            Self::UImage => "uimage",
            Self::Elf => "elf",
            Self::Fdt => "fdt",
            Self::Ubi => "ubi",
            Self::Xz => "xz",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
        }
    }

    /// Kinds with a decoder in this build. The others are reported but never carved.
    fn has_parser(self) -> bool {
        !matches!(self, Self::SquashFsBigEndian | Self::Bzip2 | Self::Zstd)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Only the signature bytes matched, or validation could not run.
    SignatureOnly,
    /// A bounded structural check of this candidate's own bytes passed.
    StructureValidated,
    /// The payload checksum of this candidate was verified.
    PayloadVerified,
    /// A parser ran and a named check failed.
    Rejected,
}

impl Status {
    pub fn is_validated(self) -> bool {
        matches!(self, Self::StructureValidated | Self::PayloadVerified)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NoParserInThisBuild,
    AttemptBudgetExhausted,
    DecodeBudgetExhausted,
    ValidationBudgetExhausted,
    ZipEndBudgetExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub id: u32,
    pub kind: CandidateKind,
    /// `None` addresses the original input; `Some(id)` addresses the verified
    /// decoded payload of that gzip candidate.
    pub container: Option<u32>,
    pub depth: u8,
    pub offset: u64,
    /// Bytes the structure occupies, when the checked fields prove it.
    pub extent: Option<u64>,
    pub status: Status,
    pub reason: Option<Reason>,
    pub checks: Vec<Check>,
    /// Smallest validated candidate that contains this one.
    pub nested_in: Option<u32>,
    /// Validated candidates that overlap this one without containing it.
    pub conflicts_with: Vec<u32>,
    /// Top-level, validated, with a proven extent and no conflict.
    pub carvable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NoSignatures,
    SignaturesWithoutValidation,
    SingleStructure,
    MultipleDisjointStructures,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepCode {
    AnalyzeCarvedCandidate,
    ResolveOverlappingCandidates,
    StructureWithoutDecoder,
    SignatureWithoutDecoder,
    BudgetExhausted,
    HighEntropyNoSignature,
    MostlyPaddingNoSignature,
    NoKnownSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextStep {
    pub code: StepCode,
    pub candidates: Vec<u32>,
    /// Fixed text selected by `code`.
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entropy {
    pub block_bytes: u32,
    pub blocks: u64,
    pub high_entropy_blocks: u64,
    pub uniform_fill_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateReport {
    pub schema_version: u32,
    pub source_sha256: String,
    pub input_bytes: u64,
    pub bounds: ScanBounds,
    pub outcome: Outcome,
    pub signature_hits: u64,
    pub hits_not_examined: u64,
    /// Hits inside a validated ZIP or SquashFS that the structure itself explains.
    pub hits_explained_by_structure: u64,
    pub validation_attempts: u64,
    pub validation_bytes: u64,
    pub zip_ends_not_examined: u64,
    pub decoded_bytes: u64,
    pub budget_exhausted: bool,
    pub entropy: Entropy,
    pub candidates: Vec<Candidate>,
    pub next_steps: Vec<NextStep>,
    pub limitation: &'static str,
}

pub(super) const LIMITATION: &str = "Signatures and header checks identify container candidates only. They do not establish a complete flash image, vendor authenticity, board identity or flashability.";

impl CandidateReport {
    /// Validated candidates in the original input that no other validated
    /// candidate contains. Nested structures are reachable through their parent.
    pub fn top_level_validated(&self) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.container.is_none() && c.status.is_validated() && c.nested_in.is_none())
            .count()
    }
}

/// Offsets of carvable candidates, for workspace publication.
pub fn carvable(report: &CandidateReport) -> impl Iterator<Item = &Candidate> {
    report.candidates.iter().filter(|c| c.carvable)
}

/// Stable one-line text for CLI output; contains only enum labels and numbers.
pub fn summary_line(candidate: &Candidate) -> String {
    let failed = candidate
        .checks
        .iter()
        .find(|check| !check.passed)
        .map(|check| format!(" failed={}", check.name))
        .unwrap_or_default();
    format!(
        "#{} {} @0x{:x}{} {:?}{}{}{}",
        candidate.id,
        candidate.kind.label(),
        candidate.offset,
        candidate
            .extent
            .map(|extent| format!(" +{extent}"))
            .unwrap_or_default(),
        candidate.status,
        failed,
        candidate
            .reason
            .map(|reason| format!(" reason={reason:?}"))
            .unwrap_or_default(),
        candidate
            .nested_in
            .map(|parent| format!(" nested_in=#{parent}"))
            .unwrap_or_default()
    )
}
