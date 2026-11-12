//! Verification of a published workspace against its integrity inventory and manifests.
use crate::{files, integrity, stage02, stage05, stage06};
use nyra_fw_core::{FirmwareManifest, FwError, Result, path::is_safe_relative};
use std::path::Path;

pub fn verify_workspace(path: &Path) -> Result<FirmwareManifest> {
    verify_with_inventory(path).map(|(manifest, _)| manifest)
}

pub(crate) fn verify_with_inventory(
    path: &Path,
) -> Result<(FirmwareManifest, integrity::Inventory)> {
    verify_internal(path, false)
}

/// Verify the current agent handoff before loading its instruction files.
pub fn verify_agent_ready(path: &Path, replay: bool) -> Result<FirmwareManifest> {
    let (manifest, inventory) = verify_internal(path, true)?;
    if replay {
        crate::replay::replay_verified(path, &manifest, &inventory)?;
    }
    Ok(manifest)
}

pub(crate) fn verify_internal(
    path: &Path,
    require_agent_ready: bool,
) -> Result<(FirmwareManifest, integrity::Inventory)> {
    let inventory = integrity::verify_snapshot(path)?;
    let manifest = verify_manifests(path, &inventory, require_agent_ready)?;
    Ok((manifest, inventory))
}

/// Cross-check typed manifests against a freshly hashed inventory. Publication
/// supplies the inventory it just wrote in its private staging directory.
pub(crate) fn verify_manifests(
    path: &Path,
    inventory: &integrity::Inventory,
    require_agent_ready: bool,
) -> Result<FirmwareManifest> {
    let manifest: FirmwareManifest =
        inventory.read_json(path, "manifests/firmware.json", files::MANIFEST_BYTES)?;
    if manifest.schema_version != 1 {
        return Err(FwError::Invalid("unsupported manifest schema".into()));
    }
    if manifest
        .summary
        .original_crc_ok
        .checked_add(manifest.summary.recovered_crc_ok)
        .is_none_or(|verified| verified > manifest.summary.eligible_entries)
    {
        return Err(FwError::Verification(
            "invalid verified member counts".into(),
        ));
    }
    if !is_safe_relative(&manifest.source.filename) || manifest.source.filename.contains('/') {
        return Err(FwError::UnsafePath(manifest.source.filename));
    }
    inventory.check(
        &format!("original/{}", manifest.source.filename),
        manifest.source.size,
        &manifest.source.sha256,
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for a in &manifest.artifacts {
        if !seen.insert(&a.path)
            || a.parent_sha256 != manifest.source.sha256
            || a.source_start
                .checked_add(a.source_length)
                .is_none_or(|end| end > manifest.source.size)
        {
            return Err(FwError::Verification(format!(
                "invalid artifact provenance: {}",
                a.path
            )));
        }
        inventory.check(&a.path, a.size, &a.sha256)?;
    }
    let analysis = stage02::verify_index(path, &manifest.source.sha256, inventory)?;
    let handoff = stage05::verify_structure(path, &manifest, &analysis, inventory)?;
    let stage06 = stage06::read(path, &manifest, inventory)?;
    let agent_ready = crate::agent_index::verify(
        path,
        &manifest,
        &analysis,
        &handoff,
        stage06.as_ref().map(|run| run.recovery_state.as_str()),
        inventory,
    )?;
    if require_agent_ready && !agent_ready {
        return Err(FwError::Verification(
            "workspace uses a legacy agent handoff; regenerate it before loading agent instructions".into(),
        ));
    }
    if require_agent_ready {
        verify_agent_root(path)?;
    }
    Ok(manifest)
}

fn verify_agent_root(path: &Path) -> Result<()> {
    use nyra_fw_core::errors::io;
    let dir = files::open_root(path)?;
    for entry in dir.entries().map_err(|error| io(path, error))? {
        let entry = entry.map_err(|error| io(path, error))?;
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|error| io(path, error))?;
        let allowed = match name.to_str() {
            Some(
                "original" | "recovered" | "analysis" | "manifests" | "reports" | "reconstruction",
            ) => kind.is_dir(),
            Some(
                "AGENTS.md" | "CLAUDE.md" | "README.md" | "FIRMWARE_MAP.md" | "HARDWARE.md"
                | "OPEN_QUESTIONS.md" | "RECOVERY_REPORT.md",
            ) => kind.is_file(),
            _ => false,
        };
        if !allowed {
            return Err(FwError::Verification(
                "unexpected workspace root entry for an agent session".into(),
            ));
        }
    }
    Ok(())
}
