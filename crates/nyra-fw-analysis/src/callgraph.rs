//! Ghidra's entry-reference edges; indirect/dynamic calls may be absent.
use nyra_fw_core::{FwError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub site: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StaticCallGraph {
    pub schema_version: u32,
    pub kind: String,
    #[serde(deserialize_with = "crate::export_limits::edges")]
    pub edges: Vec<CallEdge>,
    pub exported: usize,
}

pub fn parse_export(bytes: &[u8]) -> Result<StaticCallGraph> {
    let value: StaticCallGraph = crate::export_limits::parse(bytes)?;
    if value.schema_version != 1
        || value.kind != "static_entry_references"
        || value.exported != value.edges.len()
        || value.exported > crate::export_limits::MAX_EDGES
    {
        return Err(FwError::Verification(
            "invalid Ghidra static reference graph".into(),
        ));
    }
    Ok(value)
}
