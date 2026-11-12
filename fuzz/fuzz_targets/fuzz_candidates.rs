#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use nyra_fw_core::budget::RunBudget;
use nyra_fw_formats::candidates::{self, Status};

const STRUCTURES: &[&[u8]] = &[
    include_bytes!("../../tests/fixtures/synthetic/synthetic-fdt.dtb"),
    include_bytes!("../../tests/fixtures/synthetic/synthetic-ubi-ec.bin"),
    include_bytes!("../../tests/fixtures/synthetic/zip-fake-eocd.zip"),
    include_bytes!("../../tests/fixtures/synthetic/stdlib-firmware.gz"),
    include_bytes!("../../tests/fixtures/synthetic/tiny.squashfs"),
    include_bytes!("../../tests/fixtures/synthetic/zip-nested-stored.zip"),
    include_bytes!("../../tests/fixtures/synthetic/zip-bzip2-member.zip"),
    include_bytes!("../../tests/fixtures/synthetic/zip-zip64-member.zip"),
];

fuzz_target!(|data: &[u8]| {
    if !common::is_bounded(data) {
        return;
    }
    let mut mutated;
    let data = if let Some((&mode, edits)) = data.split_first()
        && mode & 0xf0 == 0xf0
    {
        let structure = STRUCTURES[usize::from(mode) % STRUCTURES.len()];
        mutated = b"opaque-prefix".to_vec();
        let prefix = mutated.len();
        mutated.extend_from_slice(structure);
        for edit in edits.chunks_exact(3).take(128) {
            let position = usize::from(u16::from_le_bytes([edit[0], edit[1]])) % structure.len();
            mutated[prefix + position] ^= edit[2];
        }
        &mutated
    } else {
        data
    };
    let run = RunBudget::new(common::limits(), None);
    let Ok(report) = candidates::scan(data, "00", &run) else {
        return;
    };
    // Invariants that every report must satisfy, whatever the bytes are.
    for candidate in &report.candidates {
        if let Some(extent) = candidate.extent {
            assert!(candidate.status.is_validated());
            if candidate.container.is_none() {
                assert!(candidate.offset + extent <= data.len() as u64);
                let source = nyra_fw_core::source::ByteSource::new(
                    data,
                    nyra_fw_core::source::Original { sha256: "00" },
                );
                let range = candidate
                    .original_range(source)
                    .expect("validated original range");
                assert_eq!(range.length(), extent);
            }
        }
        if candidate.carvable {
            assert!(candidate.extent.is_some() && candidate.conflicts_with.is_empty());
            assert!(candidate.nested_in.is_none() && candidate.container.is_none());
        }
        if let Some(parent) = candidate.nested_in {
            // Containment is strict, validated and inside one coordinate space.
            let outer = &report.candidates[parent as usize];
            assert!(outer.status.is_validated() && outer.container == candidate.container);
            let end = outer.offset + outer.extent.expect("a container has a proven extent");
            assert!(candidate.offset > outer.offset && candidate.offset < end);
        }
        assert!(candidate.status != Status::Rejected || candidate.checks.iter().any(|c| !c.passed));
    }
    assert!(report.validation_attempts <= candidates::BOUNDS.max_validation_attempts as u64);
    assert!(report.candidates.len() <= candidates::BOUNDS.max_candidates);
    assert!(report.validation_bytes <= candidates::BOUNDS.max_validation_bytes);
    assert!(report.decoded_bytes <= candidates::BOUNDS.max_decoded_bytes);
});
