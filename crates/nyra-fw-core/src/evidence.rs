//! Claim provenance is distinct from a CRC check and from hardware verification.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Verified,
    Derived,
    VendorClaim,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub claim: String,
    pub level: EvidenceLevel,
    pub source: String,
    pub rationale: String,
}

impl Evidence {
    pub fn derived(
        claim: impl Into<String>,
        source: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            claim: claim.into(),
            level: EvidenceLevel::Derived,
            source: source.into(),
            rationale: reason.into(),
        }
    }
}
