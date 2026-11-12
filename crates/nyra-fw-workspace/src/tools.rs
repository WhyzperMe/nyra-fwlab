//! Optional external-tool steps: sandboxed SquashFS extraction and headless Ghidra.
//!
//! Both are explicit opt-in. A failure aborts publication unless partial tool results
//! were allowed, in which case it is recorded separately from verified recovery.
use crate::pipeline_state::FilesystemState;
use crate::{
    ghidra::{self, Exports},
    report_writer::ReportWriter,
    rootfs::ROOTFS_DIR,
    sandbox,
    stage02::{Stage02Manifest, Stage02Options},
};
use nyra_fw_analysis::{binary::BinaryReport, triage};
use nyra_fw_core::{FwError, Result, budget::RunBudget, errors::io, timings::Phase};
use nyra_fw_formats::squashfs;
use serde::Serialize;
use std::{fs, path::Path};

/// Everything a tool step needs besides the report writer and the manifest.
pub(crate) struct ToolContext<'a> {
    pub root: &'a Path,
    pub run: &'a RunBudget,
    pub options: &'a Stage02Options,
    pub require_cgroup: bool,
    pub allow_partial_tools: bool,
    pub ghidra_cache: Option<&'a Path>,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum ToolOutcome {
    NotRequested,
    Completed,
    Failed {
        category: &'static str,
        detail: &'static str,
    },
}

/// Turn a tool result into an outcome. A failure is an error unless partial tool
/// results are allowed.
fn optional<T>(result: Result<T>, ctx: &ToolContext<'_>) -> Result<(Option<T>, ToolOutcome)> {
    ctx.run.checkpoint()?;
    match result {
        Ok(value) => Ok((Some(value), ToolOutcome::Completed)),
        Err(error) if ctx.allow_partial_tools => {
            let (category, detail) = match error {
                FwError::Unsupported(_) => (
                    "unsupported",
                    "Requested analysis is unavailable for this input or host.",
                ),
                FwError::Config(_) => (
                    "configuration",
                    "External analysis configuration is invalid.",
                ),
                FwError::ToolTimeout => (
                    "resource_limit",
                    "External analysis exceeded its wall-clock budget.",
                ),
                FwError::Limit(_) => (
                    "resource_limit",
                    "External analysis exceeded a resource limit.",
                ),
                FwError::Io { .. } => ("io", "External analysis encountered an I/O failure."),
                _ => (
                    "invalid_output",
                    "External analysis failed or its output did not pass validation.",
                ),
            };
            Ok((None, ToolOutcome::Failed { category, detail }))
        }
        Err(error) => Err(error),
    }
}

fn extract_squashfs(
    ctx: &ToolContext<'_>,
    image: &str,
) -> Result<(tempfile::TempDir, sandbox::Output)> {
    let stage = tempfile::tempdir_in(ctx.root).map_err(|e| io(ctx.root, e))?;
    let dest = stage.path().join("rootfs");
    fs::create_dir(&dest).map_err(|e| io(&dest, e))?;
    let output = sandbox::run(
        sandbox::Tool::SquashFs,
        &ctx.root.join(image),
        stage.path(),
        "rootfs",
        ctx.options.tool_timeout(),
        ctx.run,
        ctx.require_cgroup,
    )?;
    Ok((stage, output))
}

/// Record the validated superblock and, when requested, extract the filesystem.
pub(crate) fn squashfs_step(
    writer: &mut ReportWriter<'_>,
    manifest: &mut Stage02Manifest,
    ctx: &ToolContext<'_>,
    filesystem_image: Option<(&str, &[u8])>,
) -> Result<ToolOutcome> {
    let image = filesystem_image
        .and_then(|(name, bytes)| squashfs::inspect(bytes).map(|header| (name, header)));
    if let Some((_, header)) = &image {
        manifest.set_filesystem_state(FilesystemState::SuperblockValidated);
        writer.json(
            manifest,
            "analysis/filesystems/squashfs-superblock.json",
            header,
        )?;
    }
    if !ctx.options.extract_filesystems {
        return Ok(ToolOutcome::NotRequested);
    }
    let result = image
        .ok_or_else(|| {
            FwError::Unsupported(
                "--extract-filesystems requested, but no valid SquashFS superblock was found"
                    .into(),
            )
        })
        .and_then(|(image, header)| {
            if header.inodes as usize > ctx.run.limits.max_entries {
                return Err(FwError::Limit("SquashFS declares too many inodes".into()));
            }
            ctx.run
                .measure(Phase::SquashFs, || extract_squashfs(ctx, image))
        });
    let (output, outcome) = optional(result, ctx)?;
    let Some((stage, output)) = output else {
        manifest.set_filesystem_state(FilesystemState::Failed);
        return Ok(outcome);
    };
    let dest = ctx.root.join(ROOTFS_DIR);
    let parent = ctx.root.join("recovered/filesystems");
    fs::create_dir_all(&parent).map_err(|e| io(&parent, e))?;
    match fs::remove_dir(&dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io(&dest, err)),
    }
    crate::publish::rename_new(&stage.path().join("rootfs"), &dest)?;
    manifest.set_filesystem_state(FilesystemState::Extracted);
    writer.json(
        manifest,
        "analysis/filesystems/symlinks.json",
        &output.symlinks,
    )?;
    writer.json(
        manifest,
        "analysis/filesystems/extraction.json",
        &serde_json::json!({
            "schema_version": 1,
            "total_regular_bytes": output.bytes, "items_seen": output.entries,
            "symlinks_replaced_with_metadata": output.symlinks.len(),
            "excluded_subtrees": if output.excluded_dev { &["dev"][..] } else { &[] },
            "no_extracted_executables_were_run": true
        }),
    )?;
    Ok(outcome)
}

/// The Ghidra target and its validated exports.
pub(crate) struct GhidraResult {
    pub(crate) source: String,
    pub(crate) exports: Exports,
}

/// Choose one verified ELF and run the sandboxed headless export on it.
///
/// `verified_sources` are the ELF files recovered from the input itself. Files from an
/// opt-in extracted filesystem are indexed but are not offered as targets.
pub(crate) fn ghidra_step(
    writer: &mut ReportWriter<'_>,
    manifest: &mut Stage02Manifest,
    ctx: &ToolContext<'_>,
    binaries: &[BinaryReport],
    verified_sources: &[String],
    standalone: bool,
) -> Result<(ToolOutcome, Option<GhidraResult>)> {
    let Some(executable) = &ctx.options.ghidra_headless else {
        return Ok((ToolOutcome::NotRequested, None));
    };
    let analyze = || -> Result<GhidraResult> {
        let verified = |source: &str| verified_sources.iter().any(|name| name == source);
        let target = if let Some(requested) = &ctx.options.ghidra_target {
            binaries
                .iter()
                .find(|b| b.source == *requested && verified(&b.source))
                .ok_or_else(|| {
                    FwError::Config(format!(
                        "selected Ghidra member is not a verified ELF: {requested}"
                    ))
                })?
        } else {
            let priority = triage::prioritize(binaries);
            binaries
                .iter()
                .find(|b| b.source.ends_with("/ipc_server") && verified(&b.source))
                .or_else(|| {
                    priority.prioritized.iter().find_map(|item| {
                        binaries
                            .iter()
                            .find(|b| b.source == item.source && verified(&b.source))
                    })
                })
                .ok_or_else(|| {
                    FwError::Unsupported("Ghidra requested, but no recovered ELF was found".into())
                })?
        };
        let target_path = if standalone {
            target.source.clone()
        } else {
            format!("recovered/update/{}", target.source)
        };
        let exports = ghidra::run(
            ctx.root,
            executable,
            (&target_path, &target.sha256),
            ctx.options.tool_timeout(),
            ctx.run,
            ctx.ghidra_cache,
            ctx.require_cgroup,
        )?;
        Ok(GhidraResult {
            source: target.source.clone(),
            exports,
        })
    };
    let (result, outcome) = optional(ctx.run.measure(Phase::Ghidra, analyze), ctx)?;
    let Some(result) = result else {
        manifest.ghidra = "failed".into();
        return Ok((outcome, None));
    };
    ghidra::publish_scripts(ctx.root)?;
    writer.json(
        manifest,
        "analysis/ghidra/provenance.json",
        &result.exports.provenance,
    )?;
    for (file, bytes) in result.exports.files() {
        writer.save(manifest, &format!("analysis/ghidra/results/{file}"), bytes)?;
    }
    manifest.decompiled_functions = result.exports.decompiled;
    manifest.ghidra = format!("headless_export_complete:{}", result.source);
    Ok((outcome, Some(result)))
}
