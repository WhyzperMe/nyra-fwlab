//! Comparison with an independent reference manifest.
use crate::files;
use nyra_fw_core::{ArtifactKind, FirmwareManifest, FwError, Result};
use std::path::Path;

/// Compare all members against the Python phase-01 manifest emitted by the
/// user's original verified extractor. This requires the actual firmware and
/// recovery manifest; the shipped synthetic fixture is not a replacement.
pub fn compare_phase01_golden(manifest: &FirmwareManifest, golden_path: &Path) -> Result<usize> {
    use std::collections::BTreeMap;
    let golden_bytes = files::read_input(golden_path, 8 * 1024 * 1024)?;
    let golden: serde_json::Value = serde_json::from_slice(&golden_bytes)?;
    let expected_source = golden
        .get("firmware_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FwError::Invalid("golden manifest missing firmware_sha256".into()))?;
    if expected_source != manifest.source.sha256 {
        return Err(FwError::Verification(
            "input firmware SHA-256 differs from golden manifest".into(),
        ));
    }
    let expected_files = golden
        .get("files")
        .and_then(|v| v.as_array())
        .ok_or_else(|| FwError::Invalid("golden manifest missing files array".into()))?;
    let mut expected = BTreeMap::new();
    for entry in expected_files {
        let status = entry.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(status, "original_crc_ok" | "phase01_crc_ok") {
            continue;
        }
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FwError::Invalid("golden member missing name".into()))?;
        let sha256 = entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FwError::Invalid("golden member missing sha256".into()))?;
        if expected
            .insert(name.to_owned(), sha256.to_owned())
            .is_some()
        {
            return Err(FwError::Invalid(format!("duplicate golden member: {name}")));
        }
    }
    let actual: BTreeMap<_, _> = manifest
        .artifacts
        .iter()
        .filter(|a| a.kind == ArtifactKind::ArchiveMember)
        .map(|a| {
            (
                a.path
                    .strip_prefix("recovered/update/")
                    .unwrap_or(&a.path)
                    .to_owned(),
                a.sha256.clone(),
            )
        })
        .collect();
    if actual != expected {
        let first = expected
            .iter()
            .find(|(n, hash)| actual.get(*n) != Some(*hash))
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| "unexpected extra artifact".into());
        return Err(FwError::Verification(format!(
            "golden recovery mismatch: {first}; expected {} members, got {}",
            expected.len(),
            actual.len()
        )));
    }
    Ok(actual.len())
}
