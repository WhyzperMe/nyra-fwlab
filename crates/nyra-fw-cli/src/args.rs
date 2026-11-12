//! CLI syntax and compatibility contracts.
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "nyra-fw",
    about = "Offline, evidence-traceable firmware recovery and analysis (Stage 06)",
    version
)]
pub(crate) struct Cli {
    /// Wall-clock deadline for this invocation, including file I/O.
    #[arg(long, global = true, default_value_t = 900, value_parser = clap::value_parser!(u64).range(10..=10800))]
    pub(crate) run_timeout_seconds: u64,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum Profile {
    Auto,
    Ssc338qHichip,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Identify and structurally inspect firmware without extraction.
    Scan {
        firmware: PathBuf,
        /// Also discover embedded structures when the outer format is recognized.
        #[arg(long)]
        candidates: bool,
        #[arg(long)]
        json: bool,
    },
    /// Recover CRC-verified members into a new Claude-readable workspace.
    #[command(alias = "recover")]
    Analyze(AnalyzeArgs),
    /// Inspect Stage 03–05 evidence after one complete workspace verification.
    Inspect {
        workspace: PathBuf,
        /// Emit the stage summaries as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export a fresh evidence-only directory after replaying the source workspace.
    ExportAgent {
        workspace: PathBuf,
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Check the canonical guidance and file inventory of an agent export.
    VerifyAgentExport { directory: PathBuf },
    /// Independently re-hash the original and all recovered artifacts.
    Verify {
        workspace: PathBuf,
        /// Require the current canonical handoff before loading agent instructions.
        #[arg(long)]
        agent_ready: bool,
        /// Re-derive recovered bytes and source ranges from the original input.
        #[arg(long)]
        replay: bool,
        /// Optional original Python phase-01 recovery_manifest.json for hash-by-hash comparison.
        #[arg(long)]
        golden: Option<PathBuf>,
        /// Emit the result as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, clap::Args)]
pub(crate) struct AnalyzeArgs {
    pub(crate) firmware: PathBuf,
    #[arg(long = "workspace", alias = "output", short = 'o')]
    pub(crate) workspace: PathBuf,
    #[arg(long, value_enum, default_value_t = Profile::Auto)]
    pub(crate) profile: Profile,
    /// CPU worker threads (0 selects up to 8 automatically; maximum 16).
    #[arg(long, default_value_t = 0)]
    pub(crate) threads: usize,
    /// Allow a partial recovery, marking all failed members explicitly.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_partial: bool,
    /// Preserve the input and carve only this validated top-level candidate ID.
    #[arg(long, requires = "allow_partial")]
    pub(crate) candidate: Option<u32>,
    /// Publish verified recovery even if an explicitly requested external tool fails.
    #[arg(long)]
    pub(crate) allow_partial_tools: bool,
    /// Require a delegated Linux cgroup before starting an external tool.
    #[arg(long)]
    pub(crate) require_cgroup: bool,
    /// Opt in to sandboxed SquashFS extraction on supported Linux hosts.
    #[arg(long, default_value_t = false)]
    pub(crate) extract_filesystems: bool,
    /// Trusted Linux Ghidra installation: path to support/analyzeHeadless.
    #[arg(long)]
    pub(crate) ghidra_headless: Option<PathBuf>,
    /// Exact verified recovered ELF member to analyze (defaults to ipc_server or highest-priority ELF).
    #[arg(long, requires = "ghidra_headless")]
    pub(crate) ghidra_target: Option<String>,
    /// Trusted local directory for validated Ghidra exports. Requires NYRA_JAVA_HOME.
    #[arg(long, requires = "ghidra_headless")]
    pub(crate) ghidra_cache: Option<PathBuf>,
    /// Timeout for each opted-in external program (seconds).
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..=3600))]
    pub(crate) timeout_seconds: u64,
    /// Reuse a matching, fully verified offline workspace or start a fresh run.
    #[arg(long)]
    pub(crate) resume: bool,
    /// Emit phase timings as a separate JSON record on stderr.
    #[arg(long)]
    pub(crate) timings: bool,
    /// Emit the firmware manifest as JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_contract_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn legacy_aliases_and_global_deadline_are_preserved() {
        let cli = Cli::try_parse_from([
            "nyra-fw",
            "recover",
            "input.pkg",
            "--output",
            "workspace",
            "--profile",
            "ssc338q-hichip",
            "--threads",
            "16",
            "--allow-partial",
            "--candidate",
            "7",
            "--run-timeout-seconds",
            "120",
        ])
        .unwrap();
        assert_eq!(cli.run_timeout_seconds, 120);
        let Command::Analyze(args) = cli.command else {
            panic!("expected analyze alias")
        };
        assert_eq!(args.workspace, PathBuf::from("workspace"));
        assert!(matches!(args.profile, Profile::Ssc338qHichip));
        assert_eq!(args.threads, 16);
        assert_eq!(args.candidate, Some(7));
    }

    #[test]
    fn invalid_option_dependencies_are_rejected_before_io() {
        for extra in [
            vec!["--candidate", "0"],
            vec!["--ghidra-target", "focus"],
            vec!["--ghidra-cache", "cache"],
        ] {
            let mut args = vec!["nyra-fw", "analyze", "missing.pkg", "-o", "workspace"];
            args.extend(extra);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "nyra-fw",
                "--run-timeout-seconds",
                "0",
                "scan",
                "missing.pkg"
            ])
            .is_err()
        );
    }

    #[test]
    fn excessive_worker_counts_are_rejected_before_reading_input() {
        let cli = Cli::try_parse_from([
            "nyra-fw",
            "analyze",
            "missing.pkg",
            "-o",
            "workspace",
            "--threads",
            "17",
        ])
        .unwrap();
        let Command::Analyze(args) = cli.command else {
            panic!("expected analyze")
        };
        let error = crate::analyze::run(
            args,
            nyra_fw_core::Limits::default(),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert!(matches!(error, nyra_fw_core::FwError::Config(_)));
    }
}
