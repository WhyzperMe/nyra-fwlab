//! Stage 02: archive audit, optional bounded filesystem extraction, static ELF and
//! lens indexing, optional headless Ghidra export. It then runs the later report
//! generations (03 to 06) and the agent index, and records the run in
//! `manifests/analysis.json`. Never runs firmware binaries or writes to the camera.
use crate::{
    agent_index, binary_reports, files,
    output::{json, write_new},
    report_writer::{AnalysisFile, ReportWriter},
    rootfs, stage03, stage04, stage05, stage06,
    tools::{self, ToolContext},
};
use nyra_fw_core::{FirmwareManifest, FwError, Result, budget::RunBudget};
use nyra_fw_formats::{
    archive::{ArchiveReport, RecoveredFile},
    candidates::CandidateReport,
    central::{self, DirectoryAudit},
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) struct AnalysisInput<'a> {
    pub files: &'a [RecoveredFile],
    pub archive: ArchiveReport,
    pub archive_finding: Option<&'a nyra_fw_formats::input::ArchiveFinding<'a>>,
    pub structural_failure: Option<&'a str>,
    pub filesystem_image: Option<(&'a str, &'a [u8])>,
    pub standalone_elf: Option<(&'a str, &'a [u8])>,
    pub gzip_payload: Option<&'a [u8]>,
    pub candidates: Option<&'a nyra_fw_formats::candidates::CandidateReport>,
    pub candidate_selection: Option<&'a crate::source_map::CandidateSelection>,
    pub require_cgroup: bool,
    pub raw: &'a [u8],
    pub run: &'a RunBudget,
    pub allow_partial_tools: bool,
    pub ghidra_cache: Option<&'a Path>,
    pub cache_key: Option<&'a str>,
}

#[derive(Debug, Default, Clone)]
pub struct Stage02Options {
    /// External unsquashfs is opt-in; never implicitly execute tools on hostile input.
    pub extract_filesystems: bool,
    /// Explicit path to Ghidra's analyzeHeadless executable; none skips decompilation.
    pub ghidra_headless: Option<PathBuf>,
    /// Exact recovered ZIP member path; otherwise prefer ipc_server / highest triage.
    pub ghidra_target: Option<String>,
    pub timeout_seconds: u64,
}

impl Stage02Options {
    /// Wall-clock limit for one external tool, clamped to a sane range.
    pub(crate) fn tool_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds.clamp(10, 3600))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Stage02Manifest {
    pub schema_version: u32,
    pub source_sha256: String,
    pub central_directory_state: central::DirectoryState,
    pub squashfs: String,
    pub scanned_elfs: usize,
    pub ghidra: String,
    pub analysis_files: Vec<AnalysisFile>,
    #[serde(default)]
    pub decompiled_functions: usize,
    pub caveats: Vec<String>,
}

impl Stage02Manifest {
    pub(crate) fn filesystem_state(&self) -> Option<crate::pipeline_state::FilesystemState> {
        crate::pipeline_state::FilesystemState::parse(&self.squashfs)
    }

    pub(crate) fn set_filesystem_state(&mut self, state: crate::pipeline_state::FilesystemState) {
        self.squashfs = state.label().into();
    }

    fn new(source_sha256: &str, central_directory_state: central::DirectoryState) -> Self {
        Self {
            schema_version: 1,
            source_sha256: source_sha256.to_owned(),
            central_directory_state,
            squashfs: "not_present".into(),
            scanned_elfs: 0,
            ghidra: "not_requested".into(),
            analysis_files: Vec::new(),
            decompiled_functions: 0,
            caveats: vec!["Structural and symbol analysis does not establish a complete flash dump or working firmware.".into()],
        }
    }
}

/// Record the archive audit, the excluded records and, for unrecognized input, the
/// candidate report.
fn write_container_reports(
    writer: &mut ReportWriter<'_>,
    manifest: &mut Stage02Manifest,
    audit: &DirectoryAudit,
    issues: &[nyra_fw_formats::archive::ArchiveIssue],
    candidates: Option<&CandidateReport>,
) -> Result<()> {
    writer.json(manifest, "analysis/archive/central-directory.json", audit)?;
    writer.json(manifest, "analysis/archive/member-issues.json", issues)?;
    if let Some(candidates) = candidates {
        writer.json(manifest, "analysis/workspace/candidates.json", candidates)?;
    }
    Ok(())
}

/// Index each regular file of an extracted filesystem in the analysis checksums.
/// Extraction stores links as metadata, so no live symlink exists at publication.
fn index_extracted_files(
    root: &Path,
    run: &RunBudget,
    manifest: &mut Stage02Manifest,
    inventory: &mut rootfs::Inventory,
) -> Result<()> {
    for path in inventory.paths().unwrap_or_default().to_vec() {
        run.checkpoint()?;
        let (size, sha256) = inventory.digest(root, &path, run)?;
        manifest
            .analysis_files
            .push(AnalysisFile { path, size, sha256 });
    }
    Ok(())
}

pub(crate) fn produce_input(
    root: &Path,
    input: AnalysisInput<'_>,
    original: &FirmwareManifest,
    options: &Stage02Options,
) -> Result<(Stage02Manifest, stage05::Stage05Manifest)> {
    if options.ghidra_target.is_some() && options.ghidra_headless.is_none() {
        return Err(FwError::Config(
            "--ghidra-target requires --ghidra-headless".into(),
        ));
    }
    let AnalysisInput {
        files: members,
        archive,
        archive_finding,
        structural_failure,
        filesystem_image,
        standalone_elf,
        gzip_payload,
        candidates,
        candidate_selection,
        require_cgroup,
        raw,
        run,
        allow_partial_tools,
        ghidra_cache,
        cache_key,
    } = input;
    let ctx = ToolContext {
        root,
        run,
        options,
        require_cgroup,
        allow_partial_tools,
        ghidra_cache,
    };
    let mut writer = ReportWriter::new(root, run);
    let ArchiveReport {
        directory: audit,
        issues,
    } = archive;
    let mut manifest = Stage02Manifest::new(&original.source.sha256, audit.state.clone());
    write_container_reports(&mut writer, &mut manifest, &audit, &issues, candidates)?;
    if let Some(finding) = archive_finding {
        writer.json(&mut manifest, crate::ARCHIVE_STRUCTURE_PATH, finding)?;
    }
    if let Some(selection) = candidate_selection {
        writer.json(&mut manifest, crate::source_map::SELECTION_PATH, selection)?;
    }
    writer.json(
        &mut manifest,
        crate::byte_map::PATH,
        &crate::byte_map::derive(original, raw, candidates)?,
    )?;
    writer.json(
        &mut manifest,
        crate::component_graph::PATH,
        &crate::component_graph::derive(
            original,
            raw,
            candidates,
            &crate::component_graph::decoded_root_filesystems(members, gzip_payload),
        ),
    )?;

    let squashfs_outcome =
        tools::squashfs_step(&mut writer, &mut manifest, &ctx, filesystem_image)?;
    let extracted = matches!(squashfs_outcome, tools::ToolOutcome::Completed);

    let mut rootfs_inventory = rootfs::Inventory::discover(root, run)?;
    if extracted && rootfs_inventory.paths().is_none() {
        return Err(FwError::Verification(
            "successful extraction has no rootfs".into(),
        ));
    }
    let elfs = binary_reports::index(root, run, members, standalone_elf, &mut rootfs_inventory)?;
    binary_reports::write_reports(&mut writer, &mut manifest, &elfs)?;
    let (ghidra_outcome, ghidra_result) = tools::ghidra_step(
        &mut writer,
        &mut manifest,
        &ctx,
        &elfs.binaries,
        &elfs.recovered_sources,
        standalone_elf.is_some(),
    )?;
    if extracted {
        index_extracted_files(root, run, &mut manifest, &mut rootfs_inventory)?;
    }

    // Later report generations join the same content-addressed audit chain.
    let binaries = &elfs.binaries;
    let third = stage03::produce(
        &mut writer,
        &mut manifest,
        binaries,
        members,
        &original.source.sha256,
        ghidra_result
            .as_ref()
            .map(|result| (result.source.as_str(), &result.exports)),
    )?;
    let (fourth, hardware) = stage04::produce(
        &mut writer,
        &mut manifest,
        binaries,
        members,
        &original.source.sha256,
        run,
        &mut rootfs_inventory,
    )?;
    let handoff = stage05::produce(
        &mut writer,
        &mut manifest,
        original,
        &third,
        &fourth,
        &hardware,
        candidates,
    )?;
    stage06::produce(
        &mut writer,
        &mut manifest,
        original,
        stage06::SourceBytes {
            original: (&format!("original/{}", original.source.filename), raw),
            gzip_payload,
        },
        members,
        binaries.iter().map(|b| b.source.as_str()).collect(),
        cache_key,
    )?;
    writer.json(
        &mut manifest,
        "analysis/workspace/outcomes.json",
        &serde_json::json!({
            "schema_version": 2,
            "source_sha256": original.source.sha256,
            "container": { "format": original.detected_format, "archive_directory": audit.state, "failure": structural_failure },
            "recovery": { "verified_members": original.summary.original_crc_ok + original.summary.recovered_crc_ok,
                "failed_entries": original.summary.failed_entries, "excluded_entries": original.summary.unsupported_entries + original.summary.duplicate_names },
            "elf": { "analyzed": binaries.len(), "parse_errors": elfs.errors.len() },
            "squashfs": squashfs_outcome,
            "ghidra": ghidra_outcome,
        }),
    )?;
    agent_index::produce(&mut writer, &mut manifest, original, candidates)?;
    // The manifest is intentionally not self-hashed: circular commitments are invalid.
    write_new(root, "manifests/analysis.json", &json(&manifest)?)?;
    Ok((manifest, handoff))
}

pub(crate) fn verify_index(
    root: &Path,
    expected_source_sha256: &str,
    inventory: &crate::integrity::Inventory,
) -> Result<Stage02Manifest> {
    let manifest = inventory.read_json(root, "manifests/analysis.json", files::MANIFEST_BYTES)?;
    check_analysis(&manifest, expected_source_sha256, |file| {
        inventory.check(&file.path, file.size, &file.sha256)
    })?;
    Ok(manifest)
}

fn check_analysis(
    manifest: &Stage02Manifest,
    expected_source_sha256: &str,
    mut check: impl FnMut(&AnalysisFile) -> Result<()>,
) -> Result<()> {
    if manifest.schema_version != 1
        || manifest.source_sha256 != expected_source_sha256
        || manifest.analysis_files.len() > files::WORKSPACE_ENTRIES
    {
        return Err(FwError::Verification(
            "analysis/source manifest mismatch".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in &manifest.analysis_files {
        if !seen.insert(&file.path) || !nyra_fw_core::path::is_safe_relative(&file.path) {
            return Err(FwError::UnsafePath(format!(
                "invalid or duplicate analysis path: {}",
                file.path
            )));
        }
        check(file)?;
    }
    Ok(())
}
