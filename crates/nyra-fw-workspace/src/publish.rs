//! Publish a workspace atomically: stage in a private sibling, verify, then rename.
//! Never create executable firmware or run extracted ARM binaries.
use crate::{
    integrity, stage02, stage06,
    staging::{Preservation, RecoveredArchive, RecoveredInput},
    tree::{Publication, write_tree},
    verify::{verify_manifests, verify_with_inventory},
};
use nyra_fw_core::{
    FirmwareManifest, FwError, Result,
    budget::RunBudget,
    errors::io,
    path::is_safe_relative,
    timings::{Phase, RunTimings},
};
use nyra_fw_formats::{
    archive::ArchiveReport,
    candidates,
    input::{self, ArchiveIndex, InputKind},
    pihc::{self, RecoveryOptions},
};
use std::{fs, path::Path, sync::Arc};

fn basename_or_default(input: &Path) -> String {
    input
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| is_safe_relative(s))
        .unwrap_or("firmware.pkg")
        .to_owned()
}

#[derive(Default)]
pub struct PipelinePolicy {
    pub deadline: Option<std::time::Instant>,
    pub allow_partial_tools: bool,
    pub require_cgroup: bool,
    pub ghidra_cache: Option<std::path::PathBuf>,
    pub candidate: Option<u32>,
}

/// Auto-dispatch input formats and optionally reuse a completed, verified workspace.
pub fn publish_input(
    target: &Path,
    input_path: &Path,
    raw: &[u8],
    options: &RecoveryOptions,
    analysis: &stage02::Stage02Options,
    resume: bool,
) -> Result<(FirmwareManifest, bool)> {
    publish_input_with_policy(
        target,
        input_path,
        raw,
        options,
        analysis,
        resume,
        &PipelinePolicy::default(),
    )
}

pub fn publish_input_with_policy(
    target: &Path,
    input_path: &Path,
    raw: &[u8],
    options: &RecoveryOptions,
    analysis: &stage02::Stage02Options,
    resume: bool,
    policy: &PipelinePolicy,
) -> Result<(FirmwareManifest, bool)> {
    publish_input_observed(
        target,
        input_path,
        raw,
        options,
        analysis,
        resume,
        (policy, None),
    )
}

/// Publish with optional timing telemetry that never becomes workspace evidence.
pub fn publish_input_observed(
    target: &Path,
    input_path: &Path,
    raw: &[u8],
    options: &RecoveryOptions,
    analysis: &stage02::Stage02Options,
    resume: bool,
    observer: (&PipelinePolicy, Option<Arc<RunTimings>>),
) -> Result<(FirmwareManifest, bool)> {
    let (policy, timings) = observer;
    let run = RunBudget::new(options.limits.clone(), policy.deadline).with_timings(timings);
    run.checkpoint()?;
    options.limits.check_input(raw.len() as u64)?;
    if policy.candidate.is_some() && options.require_all {
        return Err(FwError::Config(
            "--candidate requires --allow-partial".into(),
        ));
    }
    if analysis.ghidra_target.is_some() && analysis.ghidra_headless.is_none() {
        return Err(FwError::Config(
            "--ghidra-target requires --ghidra-headless".into(),
        ));
    }
    let external = analysis.extract_filesystems || analysis.ghidra_headless.is_some();
    if policy.require_cgroup && !external {
        return Err(FwError::Config(
            "--require-cgroup requires an external analysis tool".into(),
        ));
    }
    if policy.ghidra_cache.is_some() && analysis.ghidra_headless.is_none() {
        return Err(FwError::Config(
            "Ghidra cache requires --ghidra-headless".into(),
        ));
    }
    if resume && external {
        return Err(FwError::Config(
            "--resume requires the offline analysis pipeline".into(),
        ));
    }
    let source_name = basename_or_default(input_path);
    let source_sha = run.measure(Phase::InputHash, || nyra_fw_core::sha256_hex(raw));
    let key = (!external).then(|| {
        nyra_fw_core::cache::cache_key(
            &source_sha,
            env!("CARGO_PKG_VERSION"),
            &format!(
                "{source_name:?}/{:?}/{}:{:?}/{:?}",
                options.key_mode, options.require_all, options.limits, policy.candidate,
            ),
        )
    });
    if target_exists(target)? {
        if !resume {
            return Err(FwError::AlreadyExists(target.to_path_buf()));
        }
        let manifest = run.measure(Phase::VerifyReuse, || {
            let (manifest, inventory) = verify_with_inventory(target)?;
            stage06::verify_cache(
                target,
                &manifest,
                &inventory,
                key.as_deref().unwrap_or_default(),
            )?;
            Ok::<_, FwError>(manifest)
        })?;
        run.checkpoint()?;
        return Ok((manifest, true));
    }

    let kind = input::identify(raw);
    let publication = Publication {
        source_name: &source_name,
        input_sha: &source_sha,
        raw,
        options: analysis,
        cache_key: key.as_deref(),
        run: &run,
        policy,
    };
    let manifest = publish_tree(target, &run, |stage| {
        let write = |recovered| write_tree(stage, recovered, &publication, None);
        let preserve = |mode| write(RecoveredInput::Preserved { kind, mode });
        if let Some(id) = policy.candidate {
            return preserve(Preservation::Selected(id));
        }
        // A resource limit leaves valid input undecoded: nothing is damaged and the source can
        // still be preserved and scanned within the scan's own bounds. An expired run deadline
        // is never preserved.
        let may_preserve = |err: &FwError| {
            !options.require_all
                && (!external || policy.allow_partial_tools)
                && match err {
                    FwError::Invalid(_) | FwError::Unsupported(_) | FwError::Verification(_) => {
                        true
                    }
                    FwError::Limit(_) => run.checkpoint().is_ok(),
                    _ => false,
                }
        };
        match kind {
            InputKind::Pihc => match run.measure(Phase::Recovery, || {
                pihc::recovery::recover_indexed(raw, options, &run)
            }) {
                Ok((result, report)) => write(RecoveredInput::Archive(RecoveredArchive::pihc(
                    &result, report,
                ))),
                Err(err) if may_preserve(&err) => {
                    preserve(Preservation::Fallback("pihc_recovery_failed"))
                }
                Err(err) => Err(err),
            },
            InputKind::Zip | InputKind::Tar => {
                let fallback = Preservation::Fallback(if kind == InputKind::Zip {
                    "zip_recovery_failed"
                } else {
                    "tar_recovery_failed"
                });
                let index = match input::inspect_archive(kind, raw, &run) {
                    Ok(index) => index,
                    Err(err) if may_preserve(&err) => return preserve(fallback),
                    Err(err) => return Err(err),
                };
                let finding = index.finding(&source_sha);
                let write_indexed =
                    |recovered| write_tree(stage, recovered, &publication, Some(&finding));
                match &index {
                    ArchiveIndex::Zip(zip) => {
                        let (result, issues) = match run
                            .measure(Phase::Recovery, || zip.recover(options.require_all))
                        {
                            Ok(recovered) => recovered,
                            Err(err) if may_preserve(&err) => return preserve(fallback),
                            Err(err) => return Err(err),
                        };
                        write_indexed(RecoveredInput::Archive(RecoveredArchive {
                            pihc_header: None,
                            crypto_profile: None,
                            files: &result.files,
                            summary: &result.summary,
                            failed: &result.failed_names,
                            warnings: &[],
                            report: ArchiveReport {
                                directory: result.directory,
                                issues,
                            },
                        }))
                    }
                    ArchiveIndex::Tar(tar) => write_indexed(RecoveredInput::Tar(tar.archive())),
                }
            }
            InputKind::Gzip => match run.measure(Phase::Recovery, || {
                nyra_fw_formats::gzip::decode(raw, &run.limits)
            }) {
                Ok(payload) => write(RecoveredInput::Gzip(&payload)),
                Err(err) if may_preserve(&err) => {
                    preserve(Preservation::Fallback("gzip_recovery_failed"))
                }
                Err(err) => Err(err),
            },
            _ => {
                let state = input::structural_state(kind, raw, &options.limits)?;
                if matches!(state, "magic_only" | "unrecognized") {
                    if options.require_all {
                        let scanned = candidates::scan(raw, &source_sha, &run)?;
                        return Err(FwError::Unsupported(format!(
                            "{} input lacks verified structure (candidate scan: {:?}, {} structure(s) validated); use --allow-partial to preserve the source and publish the candidate report",
                            kind.label(),
                            scanned.outcome,
                            scanned.top_level_validated()
                        )));
                    }
                    return preserve(Preservation::Fallback(state));
                }
                preserve(Preservation::Validated)
            }
        }
    })?;
    Ok((manifest, false))
}

fn target_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io(path, err)),
    }
}

pub(crate) fn publish_tree(
    target: &Path,
    run: &RunBudget,
    write: impl FnOnce(&Path) -> Result<()>,
) -> Result<FirmwareManifest> {
    publish_directory(target, run, |stage| {
        write(stage)?;
        run.measure(Phase::VerifyStage, || {
            let inventory = integrity::write_snapshot_with_budget(stage, Some(run))?;
            verify_manifests(stage, &inventory, false)
        })
    })
}

pub(crate) fn publish_directory<T>(
    target: &Path,
    run: &RunBudget,
    write: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    run.checkpoint()?;
    let filename = target
        .file_name()
        .and_then(|x| x.to_str())
        .filter(|n| is_safe_relative(n) && !n.contains('/'))
        .ok_or_else(|| FwError::UnsafePath(target.display().to_string()))?;
    if target_exists(target)? {
        return Err(FwError::AlreadyExists(target.to_path_buf()));
    }
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    let parent = fs::canonicalize(parent).map_err(|e| io(parent, e))?;
    let target = parent.join(filename);
    let mut builder = tempfile::Builder::new();
    builder.prefix(".nyra-stage-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let stage = builder.tempdir_in(&parent).map_err(|e| io(&parent, e))?;
    run.checkpoint()?;
    let manifest = write(stage.path())?;
    run.checkpoint()?;
    run.measure(Phase::Publish, || rename_new(stage.path(), &target))?;
    let _ = stage.keep();
    Ok(manifest)
}

pub(crate) fn rename_new(from: &Path, to: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let result = rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from);
    // MoveFileExW rejects an existing destination for directory moves.
    #[cfg(windows)]
    let result = fs::rename(from, to);
    #[cfg(not(any(windows, target_os = "linux", target_vendor = "apple")))]
    let result = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace directory rename unavailable",
    ));
    result.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            FwError::AlreadyExists(to.to_path_buf())
        } else if cfg!(target_os = "linux")
            && matches!(err.kind(), std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported)
        {
            FwError::Config(
                "output filesystem rejected atomic no-replace rename; choose a native Linux output directory when running under WSL".into(),
            )
        } else {
            io(to, err)
        }
    })
}
