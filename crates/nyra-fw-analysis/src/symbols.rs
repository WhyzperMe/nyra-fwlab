//! Deserialized Ghidra function export, backed by addresses in the input binary.
use nyra_fw_core::{FwError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GhidraFunction {
    pub name: String,
    pub entry: String,
    pub size: u64,
    pub external: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GhidraFunctions {
    pub schema_version: u32,
    #[serde(deserialize_with = "crate::export_limits::functions")]
    pub functions: Vec<GhidraFunction>,
    pub exported: usize,
}

pub fn parse_export(bytes: &[u8]) -> Result<GhidraFunctions> {
    let value: GhidraFunctions = crate::export_limits::parse(bytes)?;
    if value.schema_version != 1
        || value.functions.len() != value.exported
        || value.exported > crate::export_limits::MAX_FUNCTIONS
    {
        return Err(FwError::Verification(
            "inconsistent Ghidra function export".into(),
        ));
    }
    let mut entries = std::collections::BTreeSet::new();
    if value
        .functions
        .iter()
        .any(|f| f.entry.is_empty() || !entries.insert(f.entry.as_str()))
    {
        return Err(FwError::Verification(
            "empty or duplicate Ghidra function entry".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_rejects_duplicate_function_entries() {
        let raw = br#"{"schema_version":1,"exported":2,"functions":[{"name":"focus","entry":"001000","size":4,"external":false},{"name":"other","entry":"001000","size":4,"external":false}]}"#;
        assert!(parse_export(raw).is_err());
    }
}
