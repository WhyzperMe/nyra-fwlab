//! Single-pass verification of the immutable workspace before reading analysis.
//! An explicit snapshot check is not a vendor signature or source authentication.
use crate::{
    stage03::Stage03Manifest, stage04::Stage04Manifest, stage05::Stage05Manifest,
    verify::verify_with_inventory,
};
use nyra_fw_core::{FwError, Result};
use std::path::Path;

#[derive(serde::Serialize)]
pub struct WorkspaceInspection {
    pub stage03: Stage03Manifest,
    pub stage04: Stage04Manifest,
    pub stage05: Stage05Manifest,
}

/// Verify hashes and cross-manifest consistency once rather than hashing the
/// entire workspace again for every Stage 03/04/05 summary.
pub fn inspect_all_verified(root: &Path) -> Result<WorkspaceInspection> {
    let (firmware, inventory) = verify_with_inventory(root)?;
    let stage03: Stage03Manifest =
        inventory.read_json(root, "manifests/stage03.json", 2 * 1024 * 1024)?;
    let stage04: Stage04Manifest =
        inventory.read_json(root, "manifests/stage04.json", 2 * 1024 * 1024)?;
    let stage05: Stage05Manifest =
        inventory.read_json(root, "manifests/stage05.json", 2 * 1024 * 1024)?;
    if stage03.schema_version != 1
        || stage04.schema_version != 1
        || stage05.schema_version != 1
        || stage03.source_sha256 != firmware.source.sha256
        || stage04.source_sha256 != firmware.source.sha256
        || stage05.source_sha256 != firmware.source.sha256
        || stage04.source_kind != "static_offline_firmware_evidence"
    {
        return Err(FwError::Verification(
            "analysis stages disagree on source or schema".into(),
        ));
    }
    Ok(WorkspaceInspection {
        stage03,
        stage04,
        stage05,
    })
}
