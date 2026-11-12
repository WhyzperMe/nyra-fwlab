#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_formats::pihc::{CryptoVariant, crypto::restore_payload};

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) || data.len() < 6 {
        return;
    }

    let start = u16::from_le_bytes([data[0], data[1]]) as usize % data.len();
    let remaining = data.len() - start;
    let size = u16::from_le_bytes([data[2], data[3]]) as usize % (remaining + 1);
    let variant = CryptoVariant {
        phase: data[4] % 18,
        rotation: data[5] % 4,
    };
    let _ = restore_payload(data, start, size, variant);
});
