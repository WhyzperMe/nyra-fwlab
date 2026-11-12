#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_formats::pihc::{CryptoVariant, KeyMode, RecoveryOptions, recover};

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }

    let options = RecoveryOptions {
        limits: common::limits(),
        key_mode: KeyMode::Known(CryptoVariant::PHASE01),
        require_all: false,
    };
    let _ = recover(data, &options);
});
