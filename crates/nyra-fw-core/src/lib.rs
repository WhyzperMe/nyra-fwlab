//! Data contracts and safety limits shared by the offline analysis pipeline.
#![forbid(unsafe_code)]

pub mod artifact;
pub mod budget;
pub mod cache;
pub mod errors;
pub mod evidence;
pub mod limits;
pub mod manifest;
pub mod path;
pub mod source;
pub mod timings;

pub use artifact::{Artifact, ArtifactKind, Verification};
pub use errors::{FwError, Result};
pub use evidence::{Evidence, EvidenceLevel};
pub use limits::Limits;
pub use manifest::{FirmwareManifest, RecoverySummary, SourceInfo, format_label};

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
