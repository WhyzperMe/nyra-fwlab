//! Atomic publication of deterministic, verification-traceable analysis workspaces.
#![forbid(unsafe_code)]

mod agent_export;
mod agent_index;
mod binary_reports;
mod byte_map;
mod component_graph;
const ARCHIVE_STRUCTURE_PATH: &str = "analysis/archive/structure.json";
#[cfg(test)]
mod candidate_tests;
mod files;
mod ghidra;
mod golden;
mod guidance;
mod inspection;
mod integrity;
mod output;
mod pipeline_state;
mod publish;
mod replay;
mod report_writer;
pub mod reports;
mod rootfs;
mod sandbox;
#[cfg(test)]
mod schema_tests;
pub mod source_map;
pub mod stage02;
pub mod stage03;
pub mod stage04;
pub mod stage05;
mod stage06;
mod staging;
mod task_plan;
mod tools;
mod tree;
mod verify;
#[cfg(test)]
mod workspace_tests;

pub use agent_export::{export_agent, verify_agent_export};
pub use files::read_input;
pub use golden::compare_phase01_golden;
pub use inspection::{WorkspaceInspection, inspect_all_verified};
pub use publish::{
    PipelinePolicy, publish_input, publish_input_observed, publish_input_with_policy,
};
pub use replay::verify_workspace_replay;
pub use stage02::Stage02Options;
pub use verify::{verify_agent_ready, verify_workspace};
