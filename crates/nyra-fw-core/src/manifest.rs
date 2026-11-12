//! Stable JSON contracts. Schema version is explicit for future migration.
use crate::{Artifact, Evidence};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecoverySummary {
    pub signatures_seen: usize,
    pub directory_entries: usize,
    pub eligible_entries: usize,
    pub original_crc_ok: usize,
    pub recovered_crc_ok: usize,
    pub failed_entries: usize,
    pub unsupported_entries: usize,
    pub duplicate_names: usize,
    pub bytes_recovered: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub schema_version: u32,
    pub producer: String,
    pub source: SourceInfo,
    pub detected_format: String,
    pub archive_offset: u64,
    pub crypto_profile: Option<String>,
    pub summary: RecoverySummary,
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

/// Suffix that marks input preserved after it failed format validation.
const UNVERIFIED_SUFFIX: &str = "-unverified";

/// Serialized `detected_format` for a base label such as `zip`. The string form is
/// the stable manifest contract; use this and the accessors below instead of
/// matching on the suffix.
pub fn format_label(base: &str, unverified: bool) -> String {
    if unverified {
        format!("{base}{UNVERIFIED_SUFFIX}")
    } else {
        base.to_owned()
    }
}

impl FirmwareManifest {
    /// The input was preserved without passing validation for its detected format.
    pub fn is_unverified(&self) -> bool {
        self.detected_format.ends_with(UNVERIFIED_SUFFIX)
    }

    /// The format label without the unverified marker.
    pub fn format_base(&self) -> &str {
        self.detected_format
            .strip_suffix(UNVERIFIED_SUFFIX)
            .unwrap_or(&self.detected_format)
    }

    pub fn recovery_complete_for_recognized_entries(&self) -> bool {
        self.summary.eligible_entries != 0
            && self
                .summary
                .original_crc_ok
                .checked_add(self.summary.recovered_crc_ok)
                == Some(self.summary.eligible_entries)
            && self.summary.failed_entries == 0
            && self.summary.duplicate_names == 0
    }
}
