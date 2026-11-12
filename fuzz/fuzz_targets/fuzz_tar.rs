#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_core::budget::RunBudget;
use nyra_fw_formats::tar;

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }
    let run = RunBudget::new(common::limits(), None);
    if let Ok(archive) = tar::index(data, &run) {
        assert!(archive.end <= data.len());
        assert!(archive.members.len() <= run.limits.max_entries);
        for member in archive.members {
            assert!(member.offset + member.bytes.len() <= archive.end);
            assert!(nyra_fw_core::path::is_safe_relative(&member.name));
        }
    }
});
