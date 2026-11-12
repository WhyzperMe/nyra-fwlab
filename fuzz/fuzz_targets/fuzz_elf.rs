#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_analysis::binary;

fuzz_target!(|data: &[u8]| {
    if common::is_bounded(data) {
        let _ = binary::inspect("fuzz-input", data);
    }
});
