#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_formats::squashfs;

fuzz_target!(|data: &[u8]| {
    if common::is_bounded(data) {
        if let Some(image) = squashfs::inspect(data) {
            // A validated image never claims bytes beyond its input, and its tables fit inside it.
            assert!(image.bytes_used > 96 && image.bytes_used <= data.len() as u64);
        }
        let _ = nyra_fw_formats::uimage::inspect(data);
        if data.starts_with(&[0x1f, 0x8b]) {
            let _ = nyra_fw_formats::gzip::decode(data, &common::limits());
        }
    }
});
