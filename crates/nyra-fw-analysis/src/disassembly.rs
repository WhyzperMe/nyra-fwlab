//! Bounded Ghidra inferred pseudocode results. Not original source code.
use nyra_fw_core::{FwError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub name: String,
    pub entry: String,
    pub decompiled: bool,
    pub pseudocode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecompilationExport {
    pub schema_version: u32,
    pub kind: String,
    #[serde(deserialize_with = "crate::export_limits::decompiled")]
    pub functions: Vec<DecompiledFunction>,
    pub exported: usize,
    pub limited_to_lens_functions: bool,
}

pub fn parse_export(bytes: &[u8]) -> Result<DecompilationExport> {
    let value: DecompilationExport = crate::export_limits::parse(bytes)?;
    if value.schema_version != 1
        || value.kind != "inferred_pseudocode"
        || value.exported != value.functions.len()
        || value.exported > crate::export_limits::MAX_DECOMPILED
        || !value.limited_to_lens_functions
        || value.functions.iter().any(|item| {
            item.pseudocode.len() > 1_200_000 || (!item.decompiled && !item.pseudocode.is_empty())
        })
    {
        return Err(FwError::Verification(
            "invalid or oversized Ghidra decompilation".into(),
        ));
    }
    let mut entries = std::collections::BTreeSet::new();
    if value
        .functions
        .iter()
        .any(|f| f.entry.is_empty() || !entries.insert(f.entry.as_str()))
    {
        return Err(FwError::Verification(
            "empty or duplicate Ghidra decompilation entry".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_rejects_pseudocode_from_failed_decompilation() {
        let raw = br#"{"schema_version":1,"kind":"inferred_pseudocode","exported":1,"limited_to_lens_functions":true,"functions":[{"name":"focus","entry":"001000","decompiled":false,"pseudocode":"invented code"}]}"#;
        assert!(parse_export(raw).is_err());
    }
    #[test]
    fn reject_fabricated_decompilation_status() {
        assert!(parse_export(br#"{"schema_version":1,"kind":"inferred_pseudocode","exported":0,"limited_to_lens_functions":true,"functions":[{"name":"x","entry":"1","decompiled":true,"pseudocode":"x"}]}"#).is_err());
    }
}
