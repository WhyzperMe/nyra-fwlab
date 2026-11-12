//! Strictly offline ELF metadata and hardware-evidence indexing.
//! Ghidra, if enabled separately, supplies inferred pseudocode and call graphs.
#![forbid(unsafe_code)]

pub mod binary;
pub mod callgraph;
pub mod dependencies;
pub mod disassembly;
mod elf_limits;
mod export_limits;
pub mod ghidra;
pub mod hardware;
pub mod lens;
pub mod symbols;

pub mod dependency_graph;
pub mod lens_graph;
pub mod triage;

pub mod hardware_intel;
