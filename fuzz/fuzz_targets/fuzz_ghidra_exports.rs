#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_analysis::{callgraph, disassembly, ghidra, symbols};

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }

    let _ = symbols::parse_export(data);
    let _ = callgraph::parse_export(data);
    let _ = disassembly::parse_export(data);
    let defaults: [&[u8]; 3] = [
        br#"{"schema_version":1,"functions":[],"exported":0}"#,
        br#"{"schema_version":1,"kind":"static_entry_references","edges":[],"exported":0}"#,
        br#"{"schema_version":1,"kind":"inferred_pseudocode","functions":[],"exported":0,"limited_to_lens_functions":true}"#,
    ];
    for index in 0..3 {
        let mut bundle = defaults;
        bundle[index] = data;
        let _ = ghidra::parse_bundle(bundle);
    }
});
