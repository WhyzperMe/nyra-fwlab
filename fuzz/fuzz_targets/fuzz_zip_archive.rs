#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_formats::{
    central,
    input::{recover_zip, zip_structure},
    pihc::{PihcHeader, verify::decode_verified},
    zip::{safe_member_path, scan_local_entries},
};

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }

    let limits = common::limits();
    let recovered = recover_zip(data, &limits, false);
    // The extraction subset is stricter than the structure check, never looser.
    let structure = zip_structure(data, &limits);
    if recovered.is_ok() {
        assert!(structure.is_ok());
    }
    if let Ok(structure) = &structure {
        assert!(
            structure
                .member_offsets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(
            structure
                .member_offsets
                .iter()
                .all(|&offset| offset < data.len())
        );
    }
    if let Ok(name) = std::str::from_utf8(data) {
        let _ = safe_member_path(name);
    }

    let archive = PihcHeader::parse(data)
        .map(|header| header.archive(data))
        .unwrap_or(data);
    if let Ok((entries, _)) = scan_local_entries(archive, &limits) {
        let _ = central::audit(archive, &entries, &limits);
        for entry in &entries {
            let Some(end) = entry.data_offset.checked_add(entry.compressed_size) else {
                continue;
            };
            let Some(payload) = archive.get(entry.data_offset..end) else {
                continue;
            };
            let _ = decode_verified(payload, entry, &limits);
        }
    }

    let empty_entries = [];
    let _ = central::audit(data, &empty_entries, &limits);
});
