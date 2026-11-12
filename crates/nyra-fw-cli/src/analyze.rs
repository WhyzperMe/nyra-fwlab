//! Bounded analysis invocation and deterministic output presentation.
use crate::args::{AnalyzeArgs, Profile};
use crate::output::{diag, out};
use nyra_fw_core::{
    FwError, Limits, Result,
    timings::{Phase, RunTimings},
};
use nyra_fw_formats::pihc::{CryptoVariant, KeyMode, RecoveryOptions};
use nyra_fw_workspace::{PipelinePolicy, Stage02Options};
use rayon::ThreadPoolBuilder;
use std::{sync::Arc, time::Instant};

pub(crate) fn run(args: AnalyzeArgs, limits: Limits, run_deadline: Instant) -> Result<()> {
    let AnalyzeArgs {
        firmware,
        workspace,
        profile,
        threads,
        allow_partial,
        candidate,
        allow_partial_tools,
        require_cgroup,
        extract_filesystems,
        ghidra_headless,
        ghidra_target,
        ghidra_cache,
        timeout_seconds,
        resume,
        timings,
        json,
    } = args;
    if threads > 16 {
        return Err(FwError::Config("--threads must be between 0 and 16".into()));
    }
    let workers = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .min(8)
    } else {
        threads
    };
    let timings = timings.then(|| Arc::new(RunTimings::default()));
    let started = timings.as_ref().map(|_| Instant::now());
    let result = (|| {
        let read = || nyra_fw_workspace::read_input(&firmware, limits.max_input_bytes);
        let bytes = match &timings {
            Some(timings) => timings.measure(Phase::InputRead, read),
            None => read(),
        }?;
        let pool = ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .map_err(|e| FwError::Config(format!("cannot build thread pool: {e}")))?;
        let mode = match profile {
            Profile::Auto => KeyMode::Probe,
            Profile::Ssc338qHichip => KeyMode::Known(CryptoVariant::PHASE01),
        };
        let options = RecoveryOptions {
            limits,
            key_mode: mode,
            require_all: !allow_partial,
        };
        let analysis_options = Stage02Options {
            extract_filesystems,
            ghidra_headless,
            ghidra_target,
            timeout_seconds,
        };
        if !json {
            diag!("Analyzing {} bytes with {workers} worker(s)", bytes.len());
        }
        pool.install(|| {
            nyra_fw_workspace::publish_input_observed(
                &workspace,
                &firmware,
                &bytes,
                &options,
                &analysis_options,
                resume,
                (
                    &PipelinePolicy {
                        deadline: Some(run_deadline),
                        allow_partial_tools,
                        require_cgroup,
                        ghidra_cache,
                        candidate,
                    },
                    timings.clone(),
                ),
            )
        })
    })();
    if let (Some(timings), Some(started)) = (timings, started) {
        let outcome = match &result {
            Ok((_, true)) => "reused",
            Ok((_, false)) => "published",
            Err(_) => "failed",
        };
        diag!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "outcome": outcome,
                "workers": workers,
                "elapsed_ns": started.elapsed().as_nanos(),
                "phases": timings.measurements(),
            })
        );
    }
    let (manifest, reused) = result?;
    let summary = &manifest.summary;
    if !json
        && manifest
            .warnings
            .iter()
            .any(|warning| warning.starts_with("Optional analysis is incomplete."))
    {
        diag!("Optional analysis is incomplete. See analysis/workspace/outcomes.json.");
    }
    if json {
        out!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        out!(
            "{} workspace {}",
            if reused {
                "Reused verified"
            } else {
                "Published"
            },
            workspace.display()
        );
        out!(
            "Format {} | CRC-verified {} of {} eligible members | failed {} | excluded {}",
            manifest.detected_format,
            summary.original_crc_ok + summary.recovered_crc_ok,
            summary.eligible_entries,
            summary.failed_entries,
            summary.unsupported_entries + summary.duplicate_names
        );
        out!("Read CLAUDE.md and manifests/stage06.json for evidence and recovery status.");
        out!("Full flash coverage and flashability remain unverified.");
    }
    Ok(())
}
