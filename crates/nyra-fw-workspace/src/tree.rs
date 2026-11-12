//! Write the complete workspace tree for one staged input.
use crate::{
    guidance,
    output::{json, write_new},
    publish::PipelinePolicy,
    reports, source_map, stage02,
    staging::{RecoveredInput, Staged, stage_archive, stage_gzip, stage_preserved, stage_tar},
};
use nyra_fw_core::{
    FirmwareManifest, Result, SourceInfo, budget::RunBudget, errors::io, timings::Phase,
};
use nyra_fw_formats::squashfs;
use rayon::prelude::*;
use std::{fs, path::Path};

pub(crate) struct Publication<'a> {
    pub(crate) source_name: &'a str,
    pub(crate) input_sha: &'a str,
    pub(crate) raw: &'a [u8],
    pub(crate) options: &'a stage02::Stage02Options,
    pub(crate) cache_key: Option<&'a str>,
    pub(crate) run: &'a RunBudget,
    pub(crate) policy: &'a PipelinePolicy,
}

pub(crate) fn write_tree<'a>(
    root: &Path,
    recovered: RecoveredInput<'a>,
    publication: &Publication<'a>,
    archive_finding: Option<&nyra_fw_formats::input::ArchiveFinding<'_>>,
) -> Result<()> {
    let Publication {
        source_name,
        input_sha,
        raw,
        options,
        cache_key,
        run,
        policy,
    } = *publication;
    run.checkpoint()?;
    for directory in [
        "analysis/binaries",
        "analysis/hardware",
        "analysis/lens",
        "reconstruction/board-profile",
        "reconstruction/buildroot-overlay",
        "reconstruction/lens-driver",
        "reconstruction/patches",
        "recovered/containers",
        "recovered/images",
        "recovered/filesystems/rootfs",
        "recovered/unverified",
        "recovered/update",
        "reports/logs",
        "manifests",
    ] {
        let p = root.join(directory);
        fs::create_dir_all(&p).map_err(|e| io(&p, e))?;
    }
    let original_path = format!("original/{source_name}");
    let staged = run.measure(Phase::Staging, || {
        write_new(root, &original_path, raw)?;
        match recovered {
            RecoveredInput::Archive(archive) => stage_archive(root, raw, input_sha, archive),
            RecoveredInput::Gzip(payload) => stage_gzip(root, raw, input_sha, payload),
            RecoveredInput::Tar(archive) => stage_tar(root, raw, input_sha, archive, run),
            RecoveredInput::Preserved { kind, mode } => {
                stage_preserved(root, raw, input_sha, &original_path, run, kind, mode)
            }
        }
    })?;
    let Staged {
        detected,
        report,
        members: archive_members,
        failed: failed_names,
        summary,
        mut artifacts,
        mut warnings,
        evidence,
        archive_offset,
        crypto_profile,
        mut filesystem_image,
        standalone_elf,
        gzip_payload,
        structural_failure,
        candidates: candidate_report,
        candidate_selection,
    } = staged;
    if !archive_members.is_empty() {
        run.measure(Phase::Staging, || {
            run.batches(
                archive_members,
                |member| member.bytes.len() as u64 + 1024,
                |batch| {
                    let written: Result<Vec<_>> = batch
                        .par_iter()
                        .map(|member| {
                            run.checkpoint()?;
                            let artifact = source_map::recovered_artifact(
                                member,
                                input_sha,
                                crypto_profile.as_deref(),
                            );
                            write_new(root, &artifact.path, &member.bytes)?;
                            Ok(artifact)
                        })
                        .collect();
                    artifacts.extend(written?);
                    Ok(())
                },
            )
        })?;
    }
    if filesystem_image.is_none() {
        let mut images = archive_members
            .iter()
            .enumerate()
            .filter(|(_, member)| squashfs::inspect(&member.bytes).is_some());
        if let Some((index, image)) = images.next() {
            if images.next().is_none() {
                let first_member = artifacts.len() - archive_members.len();
                filesystem_image = Some((
                    artifacts[first_member + index].path.clone(),
                    image.bytes.as_slice(),
                ));
            } else {
                warnings.push("Multiple SquashFS images detected. Automatic extraction requires a unique image.".into());
            }
        }
    }
    warnings.push(
        "Full flash coverage, vendor authenticity, and flashability remain unverified.".into(),
    );
    let mut manifest = FirmwareManifest {
        schema_version: 1,
        producer: concat!("nyra-fwlab/", env!("CARGO_PKG_VERSION")).into(),
        source: SourceInfo {
            filename: source_name.into(),
            size: raw.len() as u64,
            sha256: input_sha.into(),
        },
        detected_format: detected,
        archive_offset,
        crypto_profile,
        summary,
        artifacts,
        evidence,
        warnings,
    };
    let (stage02_manifest, handoff) = run.measure(Phase::Analysis, || {
        stage02::produce_input(
            root,
            stage02::AnalysisInput {
                files: archive_members,
                archive: report,
                archive_finding,
                structural_failure,
                filesystem_image: filesystem_image
                    .as_ref()
                    .map(|(path, bytes)| (path.as_str(), *bytes)),
                standalone_elf: standalone_elf
                    .as_ref()
                    .map(|(path, bytes)| (path.as_str(), *bytes)),
                raw,
                gzip_payload,
                candidates: candidate_report.as_ref(),
                candidate_selection: candidate_selection.as_ref(),
                run,
                require_cgroup: policy.require_cgroup,
                allow_partial_tools: policy.allow_partial_tools,
                ghidra_cache: policy.ghidra_cache.as_deref(),
                cache_key,
            },
            &manifest,
            options,
        )
    })?;
    if stage02_manifest.ghidra == "failed" || stage02_manifest.squashfs == "failed" {
        manifest
            .warnings
            .push("Optional analysis is incomplete. See analysis/workspace/outcomes.json.".into());
    }
    write_new(root, "manifests/firmware.json", &json(&manifest)?)?;
    write_new(
        root,
        "manifests/artifacts.json",
        &json(&manifest.artifacts)?,
    )?;
    write_new(root, "manifests/evidence.json", &json(&manifest.evidence)?)?;
    write_new(
        root,
        "RECOVERY_REPORT.md",
        reports::summary(&manifest).as_bytes(),
    )?;
    write_new(
        root,
        "reports/summary.md",
        reports::summary(&manifest).as_bytes(),
    )?;
    write_new(root, "reports/verification.md", b"# Verification\n\nZIP member CRC32 and declared size are checked independently; source SHA-256 is recorded. Full flash layout, completeness, and provenance of vendor claims remain unverified.\n")?;
    write_new(root, "reports/missing-components.md", b"# Not established by this update\n\nBootloader, MTD layout, actual motor controller model, calibration data, and a verified board recovery procedure may be absent.\n")?;
    write_new(root, "reconstruction/README.md", b"# Reconstruction workspace\n\nPut new source code, Buildroot overlays and board profiles here. Do not modify recovered/ or original/.\n")?;
    guidance::publish_documents(root, &manifest, &stage02_manifest, &handoff)?;
    run.checkpoint()?;
    write_new(
        root,
        "manifests/recovery-status.json",
        &json(&serde_json::json!({
            "complete_for_recognized_entries": manifest.recovery_complete_for_recognized_entries(),
            "failed_names": failed_names,
            "complete_firmware_known": false,
            "flashable_image": false,
            "decompilation_performed": stage02_manifest.decompiled_functions != 0,
            "central_directory_state": &stage02_manifest.central_directory_state,
            "filesystems": &stage02_manifest.squashfs,
            "elfs_analyzed": stage02_manifest.scanned_elfs
        }))?,
    )?;
    Ok(())
}
