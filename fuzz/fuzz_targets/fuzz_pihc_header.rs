#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_formats::pihc::PihcHeader;

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }

    if let Ok(header) = PihcHeader::parse(data) {
        let _ = header.pre_archive(data);
        let _ = header.archive(data);
    }
});
