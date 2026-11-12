//! All recovered files carry source offsets, hashes, and verification state.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    FirmwareImage,
    SquashFsImage,
    ArchiveMember,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    OriginalCrc32,
    RecoveredCrc32,
    HeaderValidated,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Path relative to the generated workspace, never an absolute host path.
    pub path: String,
    pub kind: ArtifactKind,
    pub size: u64,
    pub sha256: String,
    pub verification: Verification,
    pub source_start: u64,
    pub source_length: u64,
    pub transformation: String,
    pub parent_sha256: String,
}
