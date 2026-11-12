//! The readiness-gated follow-up tasks of a workspace. Titles and rationales are
//! fixed text; the state of each task follows from typed report fields only.
use crate::{stage02::Stage02Manifest, stage03::Stage03Manifest, stage04::Stage04Manifest};
use nyra_fw_formats::candidates::Outcome;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub state: String,
    pub read_first: Vec<String>,
    pub output_area: String,
    pub rationale: String,
}

pub(crate) fn tasks(
    analysis: &Stage02Manifest,
    stage03: &Stage03Manifest,
    stage04: &Stage04Manifest,
    candidates: Option<Outcome>,
    legacy: bool,
) -> Vec<Task> {
    let mut tasks = Vec::new();
    let mut add = |id: &str, title: &str, state: &str, read: &[&str], rationale: &str| {
        tasks.push(Task {
            id: id.into(),
            title: title.into(),
            state: state.into(),
            read_first: read.iter().map(|s| (*s).to_owned()).collect(),
            output_area: "reconstruction/".into(),
            rationale: rationale.into(),
        });
    };
    add(
        "confirm-recovery",
        "Audit recovery and source offsets",
        "ready",
        &[
            "manifests/firmware.json",
            "analysis/archive/central-directory.json",
            "analysis/workspace/artifact-catalog.json",
        ],
        "CRC32 and SHA-256 verify bytes; full update completeness requires independent structural evidence.",
    );
    if let Some(outcome) = candidates {
        let actionable = matches!(
            outcome,
            Outcome::SingleStructure | Outcome::MultipleDisjointStructures
        );
        add(
            "triage-candidates",
            "Review embedded-structure candidates",
            if actionable { "ready" } else { "blocked" },
            &[
                "analysis/workspace/candidates.json",
                "manifests/artifacts.json",
            ],
            if actionable && legacy {
                "Validated structures were carved at their exact source ranges. Analyze each carve as its own input; a structure check is not authenticity."
            } else if actionable {
                "Compare validated candidates with the published artifact list. Analyze any published carve as its own input and establish authenticity independently."
            } else {
                "No unambiguous validated structure was found. The report records signatures, failed checks and the diagnosis. Do not select among overlapping candidates without independent evidence."
            },
        );
    }
    add(
        "firmware-bsp",
        "Map build requirements without flashing",
        "ready",
        &[
            "manifests/stage03.json",
            "analysis/stage03/boot-candidates.json",
            "manifests/stage04.json",
        ],
        "Treat toolchain, kernel ABI and device tree as unverified until independently checked.",
    );
    if stage04.motor_symbol_observations > 0 || stage04.i2c_path_references > 0 {
        add(
            "lens-evidence",
            "Correlate motor symbols with call graph",
            "ready",
            &[
                "analysis/hardware/lens-worklist.json",
                "analysis/lens/function-index.json",
            ],
            "A string or symbol is not proof that a controller exists or a register write is safe.",
        );
    } else {
        add(
            "lens-evidence",
            "Find verified lens command path",
            "blocked",
            &[
                "analysis/hardware/lens-worklist.json",
                "analysis/binaries/elf-index.json",
            ],
            "No indexed motor symbols or I2C paths were found; require deeper static evidence.",
        );
    }
    if analysis.filesystem_state() == Some(crate::pipeline_state::FilesystemState::Extracted) {
        add(
            "rootfs-audit",
            "Audit opt-in extracted root filesystem",
            "ready",
            &[
                "analysis/filesystems/extraction.json",
                "analysis/hardware/stage04-inventory.json",
            ],
            "Read-only extracted filesystem files are separately checksummed.",
        );
    } else {
        add(
            "rootfs-audit",
            "Extract and audit root filesystem",
            "blocked",
            &["analysis/filesystems/squashfs-superblock.json"],
            "Extraction was not requested or no supported superblock was verified.",
        );
    }
    if stage03.lens_graph_state == "static_lens_neighborhood_generated" {
        add(
            "pseudocode-review",
            "Review decompiler call graph",
            "ready",
            &[
                "analysis/ghidra/results/callgraph.json",
                "analysis/ghidra/results/pseudocode.json",
            ],
            "Decompiler output is inferred and must be checked against disassembly.",
        );
    } else {
        add(
            "pseudocode-review",
            "Run optional Ghidra evidence export",
            "blocked",
            &[
                "manifests/analysis.json",
                "analysis/lens/function-index.json",
            ],
            "Ghidra was not enabled or did not produce a verified graph.",
        );
    }
    tasks
}
