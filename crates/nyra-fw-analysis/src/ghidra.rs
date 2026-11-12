//! Admission of related Ghidra exports. This checks consistency, not tool trust
//! or the correctness of inferred pseudocode or dynamic control flow.
use crate::{callgraph, disassembly, export_limits, symbols};
use nyra_fw_core::{FwError, Result};
use std::collections::{BTreeMap, BTreeSet};

pub struct ExportBundle {
    pub functions: symbols::GhidraFunctions,
    pub calls: callgraph::StaticCallGraph,
    pub decompilation: disassembly::DecompilationExport,
}

pub fn parse_bundle(raw: [&[u8]; 3]) -> Result<ExportBundle> {
    let bytes = raw
        .iter()
        .try_fold(0usize, |sum, data| sum.checked_add(data.len()));
    if bytes.is_none_or(|bytes| bytes > 128 * 1024 * 1024) {
        return Err(FwError::Limit(
            "Ghidra export bundle exceeds 128 MiB".into(),
        ));
    }
    let bundle = ExportBundle {
        functions: symbols::parse_export(raw[0])?,
        calls: callgraph::parse_export(raw[1])?,
        decompilation: disassembly::parse_export(raw[2])?,
    };
    bundle.validate()?;
    Ok(bundle)
}

impl ExportBundle {
    fn validate(&self) -> Result<()> {
        let entries: BTreeMap<_, _> = self
            .functions
            .functions
            .iter()
            .map(|f| (f.entry.as_str(), f.name.as_str()))
            .collect();
        let names: BTreeSet<_> = entries.values().copied().collect();
        // The legacy exporter stops at 20,000 functions without a truncation
        // flag. At that boundary absence is not proof of an inconsistent export.
        let complete_index = self.functions.exported < export_limits::MAX_FUNCTIONS;
        for function in &self.decompilation.functions {
            match entries.get(function.entry.as_str()) {
                Some(name) if *name != function.name => return Err(mismatch()),
                None if complete_index => return Err(mismatch()),
                _ => {}
            }
        }
        if complete_index
            && self.calls.edges.iter().any(|edge| {
                !names.contains(edge.caller.as_str()) || !names.contains(edge.callee.as_str())
            })
        {
            return Err(mismatch());
        }
        Ok(())
    }
}

fn mismatch() -> FwError {
    FwError::Verification("Ghidra exports disagree on function identities".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUNCTIONS: &[u8] = br#"{"schema_version":1,"exported":2,"functions":[{"name":"focus","entry":"1000","size":4,"external":false},{"name":"focus","entry":"2000","size":4,"external":false}]}"#;
    const CALLS: &[u8] = br#"{"schema_version":1,"kind":"static_entry_references","exported":1,"edges":[{"caller":"focus","callee":"focus","site":"1001"}]}"#;
    const CODE: &[u8] = br#"{"schema_version":1,"kind":"inferred_pseudocode","exported":1,"limited_to_lens_functions":true,"functions":[{"name":"focus","entry":"1000","decompiled":true,"pseudocode":"inferred"}]}"#;

    #[test]
    fn permits_name_collisions_but_rejects_inconsistent_export_sets() {
        assert!(parse_bundle([FUNCTIONS, CALLS, CODE]).is_ok());
        for replacement in ["missing", "other"] {
            let calls = String::from_utf8_lossy(CALLS).replace("focus", replacement);
            assert!(parse_bundle([FUNCTIONS, calls.as_bytes(), CODE]).is_err());
        }
        for code in [
            String::from_utf8_lossy(CODE).replace("1000", "3000"),
            String::from_utf8_lossy(CODE).replace("focus", "other"),
        ] {
            assert!(parse_bundle([FUNCTIONS, CALLS, code.as_bytes()]).is_err());
        }
    }

    #[test]
    fn a_capped_function_index_does_not_establish_absence() {
        let mut functions = symbols::parse_export(FUNCTIONS).unwrap();
        for index in 2..export_limits::MAX_FUNCTIONS {
            functions.functions.push(symbols::GhidraFunction {
                name: "focus".into(),
                entry: format!("entry-{index}"),
                size: 1,
                external: false,
            });
        }
        functions.exported = functions.functions.len();
        let code = String::from_utf8_lossy(CODE).replace("1000", "unindexed");
        let calls = String::from_utf8_lossy(CALLS).replace("focus", "unindexed");
        assert!(
            parse_bundle([
                &serde_json::to_vec(&functions).unwrap(),
                calls.as_bytes(),
                code.as_bytes()
            ])
            .is_ok()
        );
        let contradictory = String::from_utf8_lossy(CODE).replace("focus", "other");
        assert!(
            parse_bundle([
                &serde_json::to_vec(&functions).unwrap(),
                CALLS,
                contradictory.as_bytes()
            ])
            .is_err()
        );
    }
}
