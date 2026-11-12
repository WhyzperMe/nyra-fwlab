//! Re-derive artifact provenance from the source rather than trusting the recorded ranges.
use crate::{
    component_graph, files,
    integrity::Inventory,
    source_map::{self, Carve},
    verify::verify_with_inventory,
};
use nyra_fw_core::{
    Artifact, FirmwareManifest, FwError, Limits, Result, budget::RunBudget, sha256_hex,
};
use nyra_fw_formats::{
    candidates, gzip,
    input::{self, ArchiveIndex, InputKind},
    pihc::{self, CryptoVariant, KeyMode, RecoveryOptions},
    uimage,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const CURRENT_PRODUCER: &str = concat!("nyra-fwlab/", env!("CARGO_PKG_VERSION"));

#[derive(Default)]
struct Replay {
    candidates: Option<candidates::CandidateReport>,
    decoded_root_filesystems: BTreeSet<String>,
}

/// Verify the immutable workspace and independently reconstruct its source-derived artifacts.
pub fn verify_workspace_replay(root: &Path) -> Result<FirmwareManifest> {
    let (manifest, inventory) = verify_with_inventory(root)?;
    replay_verified(root, &manifest, &inventory)?;
    Ok(manifest)
}

pub(crate) fn replay_verified(
    root: &Path,
    manifest: &FirmwareManifest,
    inventory: &Inventory,
) -> Result<()> {
    let limits = Limits::default();
    let source = files::read_relative(
        root,
        &format!("original/{}", manifest.source.filename),
        limits.max_input_bytes,
    )?;
    if source.len() as u64 != manifest.source.size || sha256_hex(&source) != manifest.source.sha256
    {
        return Err(FwError::Verification("source changed before replay".into()));
    }
    let selection = if inventory.contains(source_map::SELECTION_PATH) {
        if !manifest.is_unverified() {
            return Err(FwError::Verification(
                "unexpected explicit candidate selection".into(),
            ));
        }
        Some(inventory.read_json(root, source_map::SELECTION_PATH, files::MANIFEST_BYTES)?)
    } else {
        None
    };
    let replay = verify_artifacts(
        root,
        &source,
        manifest,
        limits,
        selection.as_ref(),
        inventory,
    )?;
    if inventory.contains(crate::byte_map::PATH) {
        let expected = crate::output::json(&crate::byte_map::derive(
            manifest,
            &source,
            replay.candidates.as_ref(),
        )?)?;
        inventory.check(
            crate::byte_map::PATH,
            expected.len() as u64,
            &sha256_hex(&expected),
        )?;
    } else if manifest.producer == CURRENT_PRODUCER {
        return Err(FwError::Verification(
            "current workspace lacks its byte map".into(),
        ));
    }
    check_report(inventory, manifest, component_graph::PATH, || {
        Ok(component_graph::derive(
            manifest,
            &source,
            replay.candidates.as_ref(),
            &replay.decoded_root_filesystems,
        ))
    })?;
    Ok(())
}

fn check_report<T: serde::Serialize>(
    inventory: &Inventory,
    manifest: &FirmwareManifest,
    path: &str,
    derive: impl FnOnce() -> Result<T>,
) -> Result<()> {
    if inventory.contains(path) {
        let expected = crate::output::json(&derive()?)?;
        inventory.check(path, expected.len() as u64, &sha256_hex(&expected))
    } else if manifest.producer == CURRENT_PRODUCER {
        Err(FwError::Verification(format!(
            "current workspace lacks {path}"
        )))
    } else {
        Ok(())
    }
}

fn verify_artifacts(
    root: &Path,
    raw: &[u8],
    manifest: &FirmwareManifest,
    limits: Limits,
    selection: Option<&source_map::CandidateSelection>,
    inventory: &Inventory,
) -> Result<Replay> {
    let kind = input::identify(raw);
    let previous_tar_fallback = kind == InputKind::Tar
        && manifest.detected_format == "unknown-unverified"
        && manifest.producer != CURRENT_PRODUCER;
    if manifest.format_base() != kind.label() && !previous_tar_fallback {
        return Err(FwError::Verification(
            "replay input format differs from the format recorded in the manifest".into(),
        ));
    }
    if inventory.contains(crate::ARCHIVE_STRUCTURE_PATH)
        && (manifest.is_unverified() || !matches!(kind, InputKind::Zip | InputKind::Tar))
    {
        return Err(FwError::Verification(
            "unexpected standalone archive structure report".into(),
        ));
    }
    if manifest.is_unverified() {
        return Ok(Replay {
            candidates: Some(verify_preserved(root, raw, manifest, limits, selection)?),
            ..Replay::default()
        });
    }
    if kind != InputKind::Pihc
        && (manifest.archive_offset != 0 || manifest.crypto_profile.is_some())
    {
        return Err(FwError::Verification(
            "unexpected PIHC provenance in standalone input".into(),
        ));
    }
    let run = RunBudget::new(limits.clone(), None);
    let source = manifest.source.sha256.as_str();
    let mut replay = Replay::default();
    let mut inspected_end = None;
    let expected: Vec<Artifact> = match kind {
        InputKind::Pihc => {
            let mode = match manifest.crypto_profile.as_deref() {
                Some(label) => {
                    let variant = (0..16)
                        .flat_map(|phase| {
                            (0..3).map(move |rotation| CryptoVariant { phase, rotation })
                        })
                        .find(|variant| variant.label() == label)
                        .ok_or_else(|| {
                            FwError::Verification("unknown replay crypto profile".into())
                        })?;
                    KeyMode::Known(variant)
                }
                None => KeyMode::Probe,
            };
            let options = RecoveryOptions {
                limits,
                key_mode: mode,
                require_all: false,
            };
            let (recovered, _) = pihc::recovery::recover_indexed(raw, &options, &run)?;
            replay.decoded_root_filesystems =
                component_graph::decoded_root_filesystems(&recovered.files, None);
            let profile = recovered.selected_variant.map(CryptoVariant::label);
            if recovered.header.archive_offset as u64 != manifest.archive_offset
                || profile != manifest.crypto_profile
            {
                return Err(FwError::Verification(
                    "PIHC replay header or crypto profile mismatch".into(),
                ));
            }
            let start = pihc::header::HEADER_SIZE;
            let pre = recovered.header.pre_archive(raw);
            [
                Carve::PihcHeader.artifact(&raw[..start], source, (0, start as u64)),
                Carve::PihcPreArchive {
                    squashfs: recovered.header.pre_archive_is_squashfs,
                }
                .artifact(pre, source, (start as u64, pre.len() as u64)),
            ]
            .into_iter()
            .chain(
                recovered
                    .files
                    .iter()
                    .map(|file| source_map::recovered_artifact(file, source, profile.as_deref())),
            )
            .collect()
        }
        InputKind::Zip | InputKind::Tar => {
            let archive = input::inspect_archive(kind, raw, &run)?;
            check_report(inventory, manifest, crate::ARCHIVE_STRUCTURE_PATH, || {
                Ok(archive.finding(source))
            })?;
            match archive {
                ArchiveIndex::Zip(zip) => {
                    let (recovered, _) = zip.recover(false)?;
                    replay.decoded_root_filesystems =
                        component_graph::decoded_root_filesystems(&recovered.files, None);
                    recovered
                        .files
                        .iter()
                        .map(|file| source_map::recovered_artifact(file, source, None))
                        .collect()
                }
                ArchiveIndex::Tar(tar) => tar
                    .archive()
                    .members
                    .iter()
                    .map(|member| source_map::tar_member(member, source))
                    .collect(),
            }
        }
        InputKind::UImage => {
            let image = uimage::inspect(raw).ok_or_else(|| {
                FwError::Verification("uImage replay failed integrity checks".into())
            })?;
            let start = uimage::HEADER_SIZE;
            let end = start + image.payload_bytes as usize;
            inspected_end = Some(end);
            let bytes = &raw[start..end];
            vec![Carve::UImage.artifact(bytes, source, (start as u64, bytes.len() as u64))]
        }
        InputKind::Gzip => {
            let bytes = gzip::decode(raw, &limits)?;
            replay.decoded_root_filesystems =
                component_graph::decoded_root_filesystems(&[], Some(&bytes));
            vec![Carve::Gzip.artifact(&bytes, source, (0, raw.len() as u64))]
        }
        InputKind::SquashFs => {
            let header = nyra_fw_formats::squashfs::inspect(raw).ok_or_else(|| {
                FwError::Verification("replayed SquashFS superblock fails validation".into())
            })?;
            inspected_end = Some(header.bytes_used as usize);
            Vec::new()
        }
        InputKind::ElfCandidate => Vec::new(),
        InputKind::Unknown => {
            return Err(FwError::Unsupported(
                "source replay requires a recognized or preserved-unverified input".into(),
            ));
        }
    };
    compare_artifacts(&expected, manifest)?;
    if kind == InputKind::Tar
        || (inventory.contains(crate::byte_map::PATH)
            && inspected_end.is_some_and(|end| source_map::has_non_fill_tail(raw, end)))
    {
        replay.candidates = Some(replay_candidates(root, raw, source, &run)?);
    }
    Ok(replay)
}

/// Re-derive the candidate report and its raw carves for an input that failed
/// validation, and compare both with the published workspace.
fn verify_preserved(
    root: &Path,
    raw: &[u8],
    manifest: &FirmwareManifest,
    limits: Limits,
    selection: Option<&source_map::CandidateSelection>,
) -> Result<candidates::CandidateReport> {
    if manifest.archive_offset != 0 || manifest.crypto_profile.is_some() {
        return Err(FwError::Verification(
            "unexpected PIHC provenance in preserved input".into(),
        ));
    }
    let source = manifest.source.sha256.as_str();
    let max_total = limits.max_total_output_bytes;
    let run = RunBudget::new(limits, None);
    let report = replay_candidates(root, raw, source, &run)?;
    let carves = if let Some(selection) = selection {
        vec![source_map::selected_carve(
            &report, raw, selection, max_total,
        )?]
    } else {
        source_map::candidate_carves(&report, raw, max_total)
    };
    let expected: Vec<Artifact> = carves
        .into_iter()
        .map(|(candidate, bytes)| source_map::candidate_artifact(candidate, bytes, source))
        .collect();
    compare_artifacts(&expected, manifest)?;
    Ok(report)
}

fn replay_candidates(
    root: &Path,
    raw: &[u8],
    source: &str,
    run: &RunBudget,
) -> Result<candidates::CandidateReport> {
    let stored: serde_json::Value = serde_json::from_slice(
        &files::read_relative(
            root,
            "analysis/workspace/candidates.json",
            files::REPORT_BYTES,
        )
        .map_err(|_| {
            FwError::Verification("preserved workspace lacks a candidate report to replay".into())
        })?,
    )?;
    if stored["schema_version"].as_u64() != Some(u64::from(candidates::SCHEMA_VERSION)) {
        return Err(FwError::Unsupported(
            "candidate replay requires the current scanner schema; regenerate from the verified original".into(),
        ));
    }
    let report = candidates::scan(raw, source, run)?;
    if stored != serde_json::to_value(&report)? {
        return Err(FwError::Verification(
            "candidate report differs from the report derived from the source".into(),
        ));
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) fn verify_preserved_for_test(
    root: &Path,
    raw: &[u8],
    manifest: &FirmwareManifest,
) -> Result<()> {
    verify_preserved(root, raw, manifest, Limits::default(), None).map(|_| ())
}

fn compare_artifacts(expected: &[Artifact], manifest: &FirmwareManifest) -> Result<()> {
    let mut claimed: BTreeMap<_, _> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect();
    for actual in expected {
        if claimed.remove(actual.path.as_str()) != Some(actual) {
            return Err(FwError::Verification(format!(
                "replayed artifact or provenance mismatch: {}",
                actual.path
            )));
        }
    }
    if let Some((path, _)) = claimed.first_key_value() {
        return Err(FwError::Verification(format!(
            "artifact absent from source replay: {path}"
        )));
    }
    Ok(())
}
