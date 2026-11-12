//! Invocation deadline and command dispatch.
use crate::args::{Cli, Command};
use crate::output::{diag, out};
use clap::Parser;
use nyra_fw_core::{FwError, Limits, Result, budget::RunBudget};

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    let (_completed, deadline) = std::sync::mpsc::channel::<()>();
    let seconds = cli.run_timeout_seconds;
    let run_deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    std::thread::Builder::new()
        .name("nyra-deadline".into())
        .spawn(move || {
            if deadline.recv_timeout(std::time::Duration::from_secs(seconds))
                == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                diag!("nyra-fw: invocation exceeded {seconds} seconds");
                std::process::exit(124);
            }
        })
        .map_err(|e| FwError::Config(format!("cannot start invocation timer: {e}")))?;
    let limits = Limits::default();
    match cli.command {
        Command::ExportAgent { workspace, output } => {
            let run = RunBudget::new(limits, Some(run_deadline));
            let count = nyra_fw_workspace::export_agent(&workspace, &output, &run)?;
            out!("Exported {count} evidence reports after source replay.");
        }
        Command::VerifyAgentExport { directory } => {
            let count = nyra_fw_workspace::verify_agent_export(&directory)?;
            out!("Agent export verified with {count} evidence reports.");
        }
        Command::Scan {
            firmware,
            candidates,
            json,
        } => {
            crate::scan::run(firmware, candidates, json, limits, run_deadline)?;
        }
        Command::Analyze(args) => crate::analyze::run(args, limits, run_deadline)?,
        Command::Inspect { workspace, json } => {
            let inspected = nyra_fw_workspace::inspect_all_verified(&workspace)?;
            if json {
                out!("{}", serde_json::to_string_pretty(&inspected)?);
                return Ok(());
            }
            let summary = &inspected.stage03;
            out!("Firmware SHA-256: {}", summary.source_sha256);
            out!(
                "ELF objects: {} | DT_NEEDED: {} | missing candidates: {} | ambiguous: {}",
                summary.analyzed_elfs,
                summary.dependency_references,
                summary.dependencies_not_in_recovered_set,
                summary.ambiguous_dependency_candidates
            );
            out!(
                "Boot/config candidates: {} | lens graph: {}",
                summary.boot_candidates,
                summary.lens_graph_state
            );
            for report in &summary.reports {
                out!("  {}", report);
            }
            let hardware = &inspected.stage04;
            out!(
                "Hardware components: {} | module ABI clues: {} | evidence observations: {} | motor symbols: {} | I2C paths: {}",
                hardware.indexed_components,
                hardware.indexed_module_metadata,
                hardware.indexed_observations,
                hardware.motor_symbol_observations,
                hardware.i2c_path_references
            );
            out!(
                "RootFS: {} | Hardware verified on device: NO",
                hardware.rootfs_state
            );
            for report in &hardware.reports {
                out!("  {}", report);
            }
            let handoff = &inspected.stage05;
            out!(
                "Stage 05 profile: {} (format inference, not physical hardware identity)",
                handoff.detected_profile
            );
            out!(
                "Claude handoff: {} artifacts | {} ready / {} blocked tasks",
                handoff.catalog_entries,
                handoff.ready_tasks,
                handoff.blocked_tasks
            );
            for report in &handoff.reports {
                out!("  {}", report);
            }
            out!(
                "NOTE: All values are static observations and candidate mappings, not hardware validation."
            );
        }
        Command::Verify {
            workspace,
            golden,
            replay,
            json,
            agent_ready,
        } => {
            let manifest = if agent_ready {
                nyra_fw_workspace::verify_agent_ready(&workspace, replay)?
            } else if replay {
                nyra_fw_workspace::verify_workspace_replay(&workspace)?
            } else {
                nyra_fw_workspace::verify_workspace(&workspace)?
            };
            let golden_entries = golden
                .map(|path| nyra_fw_workspace::compare_phase01_golden(&manifest, &path))
                .transpose()?;
            if json {
                // Every check above succeeded; a failure exits non-zero with no JSON.
                out!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema_version": 1,
                        "status": "pass",
                        "source_sha256": manifest.source.sha256,
                        "artifacts_verified": manifest.artifacts.len(),
                        "replay_performed": replay,
                        "golden_entries_matched": golden_entries,
                        "complete_firmware_established": false
                    }))?
                );
                return Ok(());
            }
            out!(
                "PASS: original source and {} artifacts match recorded SHA-256 hashes.",
                manifest.artifacts.len()
            );
            if agent_ready {
                out!("AGENT HANDOFF PASS: guidance and task plan match the canonical generator.");
            }
            if replay {
                out!(
                    "REPLAY PASS: {} artifacts match source-derived bytes and provenance.",
                    manifest.artifacts.len()
                );
            }
            if let Some(count) = golden_entries {
                out!(
                    "GOLDEN PASS: {count} recovered entries match reference SHA-256 hashes and filenames."
                );
            }
            out!("Full firmware completeness: not established.");
        }
    }
    Ok(())
}
