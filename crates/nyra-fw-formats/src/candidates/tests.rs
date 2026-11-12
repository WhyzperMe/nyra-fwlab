//! Behavior of candidate discovery on synthetic structures and hostile bytes.
use super::*;
use flate2::{Compression, write::GzEncoder};
use nyra_fw_core::{FwError, Limits, budget::RunBudget};
use sha2::Digest;
use std::io::Write;

const ZIP: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic/central-valid.zip");
const PIHC: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic/pihc-phase01.pkg");
/// Python `zipfile` with one bzip2 member: a method this build cannot decode.
const ZIP_BZIP2: &[u8] =
    include_bytes!("../../../../tests/fixtures/synthetic/zip-bzip2-member.zip");
/// Python `zipfile`: a stored member that is itself a complete ZIP archive.
const ZIP_NESTED: &[u8] =
    include_bytes!("../../../../tests/fixtures/synthetic/zip-nested-stored.zip");
/// Python `zipfile` with `force_zip64`: marker sizes and a ZIP64 extra field.
const ZIP_ZIP64: &[u8] =
    include_bytes!("../../../../tests/fixtures/synthetic/zip-zip64-member.zip");
/// `mksquashfs` 4.6.1 output: a real image whose metadata tables line up.
const SQUASHFS_REAL: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic/tiny.squashfs");

fn run() -> RunBudget {
    RunBudget::new(Limits::default(), None)
}

fn scanned(raw: &[u8]) -> CandidateReport {
    scan(raw, &nyra_fw_core::sha256_hex(raw), &run()).unwrap()
}

#[test]
fn checked_ranges_cannot_mix_original_and_decoded_coordinates() {
    use nyra_fw_core::source::{ByteSource, DecodedGzip, Original};
    let report = scanned(ZIP);
    let mut candidate = find(&report, CandidateKind::Zip, 0).clone();
    let source = ByteSource::new(
        ZIP,
        Original {
            sha256: &report.source_sha256,
        },
    );
    assert_eq!(candidate.original_range(source).unwrap().bytes(), ZIP);
    let decoded = DecodedGzip {
        source_sha256: &report.source_sha256,
        candidate_id: 42,
    };
    assert!(candidate.decoded_range(ZIP, decoded).is_none());
    candidate.container = Some(42);
    assert!(candidate.original_range(source).is_none());
    assert_eq!(candidate.decoded_range(ZIP, decoded).unwrap().bytes(), ZIP);
    assert!(
        candidate
            .decoded_range(
                ZIP,
                DecodedGzip {
                    candidate_id: 41,
                    ..decoded
                }
            )
            .is_none()
    );
    candidate.offset = u64::MAX;
    assert!(candidate.decoded_range(ZIP, decoded).is_none());
}

fn find(report: &CandidateReport, kind: CandidateKind, offset: u64) -> &Candidate {
    report
        .candidates
        .iter()
        .find(|c| c.kind == kind && c.offset == offset && c.container.is_none())
        .unwrap_or_else(|| panic!("no {kind:?} at {offset}: {:#?}", report.candidates))
}

/// A minimal SquashFS 4.0 image of `len` (at least 134) bytes. Superblock and a data area come
/// first. The tables follow in the order `mksquashfs` writes them and end the image: an inode
/// block, a directory block, an id block and the id index that names it.
fn squashfs(len: usize) -> Vec<u8> {
    let mut image = vec![0u8; len];
    image[..4].copy_from_slice(b"hsqs");
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[12..16].copy_from_slice(&131_072u32.to_le_bytes());
    image[20..22].copy_from_slice(&1u16.to_le_bytes());
    image[22..24].copy_from_slice(&17u16.to_le_bytes());
    image[26..28].copy_from_slice(&1u16.to_le_bytes());
    image[28..30].copy_from_slice(&4u16.to_le_bytes());
    image[40..48].copy_from_slice(&(len as u64).to_le_bytes());
    for at in [56, 80, 88] {
        image[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    }
    let inode = len - 38;
    let (directory, id_block, id_index) = (inode + 16, inode + 24, inode + 30);
    image[48..56].copy_from_slice(&(id_index as u64).to_le_bytes());
    image[64..72].copy_from_slice(&(inode as u64).to_le_bytes());
    image[72..80].copy_from_slice(&(directory as u64).to_le_bytes());
    // Uncompressed metadata blocks (bit 15) of stored size 14, 6 and 4.
    for (at, size) in [(inode, 14u16), (directory, 6), (id_block, 4)] {
        image[at..at + 2].copy_from_slice(&(0x8000 | size).to_le_bytes());
    }
    image[id_index..id_index + 8].copy_from_slice(&(id_block as u64).to_le_bytes());
    image
}

fn uimage(payload: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 64];
    image[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    image[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    image[24..28].copy_from_slice(&crc32fast::hash(payload).to_be_bytes());
    image[28..32].copy_from_slice(&[5, 2, 2, 0]);
    let header_crc = crc32fast::hash(&image);
    image[4..8].copy_from_slice(&header_crc.to_be_bytes());
    image.extend_from_slice(payload);
    image
}

fn elf() -> Vec<u8> {
    let mut image = vec![0u8; 128];
    image[..4].copy_from_slice(b"\x7fELF");
    image[4..7].copy_from_slice(&[2, 1, 1]);
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    // One PT_LOAD segment covering the whole file.
    image[64..68].copy_from_slice(&1u32.to_le_bytes());
    image[96..104].copy_from_slice(&128u64.to_le_bytes());
    image
}

fn fdt() -> Vec<u8> {
    let mut image = vec![0u8; 72];
    let words = [0xd00d_feedu32, 72, 56, 72, 40, 17, 16, 0, 0, 16];
    for (index, word) in words.iter().enumerate() {
        image[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    image[56..60].copy_from_slice(&1u32.to_be_bytes());
    image[64..68].copy_from_slice(&2u32.to_be_bytes());
    image[68..72].copy_from_slice(&9u32.to_be_bytes());
    image
}

fn ubi() -> Vec<u8> {
    let mut image = vec![0u8; 64];
    image[..4].copy_from_slice(b"UBI#");
    image[4] = 1;
    image[16..20].copy_from_slice(&64u32.to_be_bytes());
    image[20..24].copy_from_slice(&128u32.to_be_bytes());
    let crc = !crc32fast::hash(&image[..60]);
    image[60..64].copy_from_slice(&crc.to_be_bytes());
    image
}

fn xz() -> Vec<u8> {
    let mut image = vec![0xfd, b'7', b'z', b'X', b'Z', 0, 0, 4];
    image.extend_from_slice(&crc32fast::hash(&[0, 4]).to_le_bytes());
    image
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

fn flash_image() -> (Vec<u8>, Vec<(CandidateKind, u64, u64)>) {
    let mut image = Vec::new();
    let mut expected = Vec::new();
    let pad = |image: &mut Vec<u8>| image.extend(std::iter::repeat_n(0xff, 100));
    for (kind, part) in [
        (CandidateKind::SquashFs, squashfs(200)),
        (CandidateKind::Gzip, gzip(&[7; 512])),
        (CandidateKind::UImage, uimage(b"kernel payload")),
        (CandidateKind::Elf, elf()),
        (CandidateKind::Fdt, fdt()),
        (CandidateKind::Zip, ZIP.to_vec()),
    ] {
        pad(&mut image);
        expected.push((kind, image.len() as u64, part.len() as u64));
        image.extend_from_slice(&part);
    }
    pad(&mut image);
    (image, expected)
}

#[test]
fn independent_structures_are_validated_with_exact_extents() {
    let (image, expected) = flash_image();
    let report = scanned(&image);
    for (kind, offset, extent) in expected {
        let candidate = find(&report, kind, offset);
        assert!(candidate.status.is_validated(), "{candidate:?}");
        assert_eq!(candidate.extent, Some(extent), "{kind:?}");
        assert!(candidate.carvable && candidate.conflicts_with.is_empty());
    }
    assert_eq!(report.outcome, Outcome::MultipleDisjointStructures);
    assert_eq!(
        find(
            &report,
            CandidateKind::UImage,
            100 + 200 + 100 + gzip(&[7; 512]).len() as u64 + 100
        )
        .status,
        Status::PayloadVerified
    );
    assert!(
        report
            .next_steps
            .iter()
            .any(|s| s.code == StepCode::AnalyzeCarvedCandidate)
    );
    assert!(!report.budget_exhausted);
}

#[test]
fn rejected_candidates_name_the_failed_check_and_are_never_carved() {
    let mut damaged_squashfs = squashfs(200);
    damaged_squashfs[28] = 3;
    let mut damaged_uimage = uimage(b"kernel payload");
    *damaged_uimage.last_mut().unwrap() ^= 1;
    let mut damaged_gzip = gzip(&[9; 300]);
    let crc = damaged_gzip.len() - 8;
    damaged_gzip[crc] ^= 1;
    let mut short_elf = elf();
    short_elf.truncate(100);
    let mut bad_fdt = fdt();
    bad_fdt[68..72].copy_from_slice(&0u32.to_be_bytes());
    let mut bad_ubi = ubi();
    bad_ubi[8] ^= 1;
    let mut image = Vec::new();
    let mut at = Vec::new();
    for part in [
        &damaged_squashfs,
        &damaged_uimage,
        &damaged_gzip,
        &short_elf,
        &bad_fdt,
        &bad_ubi,
    ] {
        at.push(image.len() as u64);
        image.extend_from_slice(part);
        image.extend_from_slice(&[0xaa; 17]);
    }
    let report = scanned(&image);
    let expect = [
        (CandidateKind::SquashFs, at[0], "squashfs_version_4_0"),
        (CandidateKind::UImage, at[1], "uimage_payload_crc32"),
        (
            CandidateKind::Gzip,
            at[2],
            "gzip_header_deflate_crc32_isize",
        ),
        (CandidateKind::Elf, at[3], "elf_segments_within_input"),
        (CandidateKind::Fdt, at[4], "fdt_structure_tokens"),
        (CandidateKind::Ubi, at[5], "ubi_header_crc32"),
    ];
    for (kind, offset, check) in expect {
        let candidate = find(&report, kind, offset);
        assert_eq!(candidate.status, Status::Rejected, "{kind:?}");
        assert_eq!(
            candidate.checks.last().map(|c| (c.name, c.passed)),
            Some((check, false))
        );
        assert!(!candidate.carvable && candidate.extent.is_none());
    }
    assert_eq!(report.outcome, Outcome::SignaturesWithoutValidation);
    assert!(carvable(&report).next().is_none());
}

#[test]
fn overlapping_validated_structures_stay_ambiguous() {
    // Image B starts inside A's payload and ends after A ends, and both checksums verify.
    // A SquashFS cannot take part: its tables end the image, so overlapping bytes break it.
    let image_b = uimage(&[0x5a; 256]);
    let mut payload_a = vec![0xa5; 64];
    payload_a.extend_from_slice(&image_b[..image_b.len() / 2]);
    let image_a = uimage(&payload_a);
    let start_b = 64 + 64;
    let mut image = image_a[..start_b].to_vec();
    image.extend_from_slice(&image_b);
    let report = scanned(&image);
    let first = find(&report, CandidateKind::UImage, 0);
    let second = find(&report, CandidateKind::UImage, start_b as u64);
    assert_eq!(first.conflicts_with, [second.id]);
    assert_eq!(second.conflicts_with, [first.id]);
    assert!(!first.carvable && !second.carvable);
    assert_eq!(report.outcome, Outcome::Ambiguous);
    assert!(
        report
            .next_steps
            .iter()
            .any(|s| s.code == StepCode::ResolveOverlappingCandidates)
    );
    // Two different structures claiming the same first byte conflict as well.
    let mut same_start = fdt();
    same_start[..4].copy_from_slice(b"hsqs");
    assert_eq!(report_of_hits(&same_start), 1);
}

fn report_of_hits(raw: &[u8]) -> u64 {
    scanned(raw).signature_hits
}

#[test]
fn contained_structures_are_nested_not_carved_separately() {
    let mut image = squashfs(400);
    image[128..256].copy_from_slice(&elf());
    let report = scanned(&image);
    let parent = find(&report, CandidateKind::SquashFs, 0);
    let child = find(&report, CandidateKind::Elf, 128);
    assert_eq!(child.nested_in, Some(parent.id));
    assert!(parent.carvable && !child.carvable);
    assert_eq!(report.outcome, Outcome::SingleStructure);
}

#[test]
fn block_streams_inside_a_validated_squashfs_are_explained_not_listed() {
    let mut image = squashfs(400);
    image[200..200 + xz().len()].copy_from_slice(&xz());
    let after = image.len() as u64 + 16;
    image.extend_from_slice(&[0xff; 16]);
    image.extend_from_slice(&xz());
    let report = scanned(&image);
    assert_eq!(report.hits_explained_by_structure, 1);
    assert_eq!(report.top_level_validated(), 2);
    let xz_offsets: Vec<_> = report
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::Xz)
        .map(|c| c.offset)
        .collect();
    assert_eq!(xz_offsets, [after]);
    assert!(!report.budget_exhausted);
}

#[test]
fn verified_gzip_payload_is_scanned_one_level_deeper() {
    let mut payload = vec![0u8; 64];
    payload.extend_from_slice(&squashfs(200));
    let mut image = vec![0xffu8; 32];
    image.extend_from_slice(&gzip(&payload));
    let report = scanned(&image);
    let outer = find(&report, CandidateKind::Gzip, 32);
    let inner = report
        .candidates
        .iter()
        .find(|c| c.kind == CandidateKind::SquashFs)
        .unwrap();
    assert_eq!(
        (inner.container, inner.depth, inner.offset),
        (Some(outer.id), 1, 64)
    );
    assert!(inner.status.is_validated() && !inner.carvable);
    // Deflate stores incompressible data, so nested streams stay visible in the
    // source. Whatever the nesting, no candidate lies beyond the depth bound.
    let mut deep = gzip(&squashfs(200));
    for _ in 0..4 {
        deep = gzip(&deep);
    }
    let report = scanned(&deep);
    assert_eq!(
        report.candidates.iter().map(|c| c.depth).max(),
        Some(BOUNDS.max_depth)
    );
    let outermost = find(&report, CandidateKind::Gzip, 0);
    assert!(
        report
            .candidates
            .iter()
            .filter(|c| c.container.is_none() && c.offset != 0)
            .all(|c| c.nested_in == Some(outermost.id) || c.nested_in.is_some())
    );
    assert!(carvable(&report).count() == 1);
}

#[test]
fn embedded_zip_needs_its_own_end_record_and_pihc_has_no_extent() {
    let mut image = vec![0u8; 100];
    image.extend_from_slice(ZIP);
    image.extend_from_slice(&[0x55; 100]);
    let zip = find(&scanned(&image), CandidateKind::Zip, 100).clone();
    assert_eq!((zip.extent, zip.carvable), (Some(ZIP.len() as u64), true));
    let truncated = scanned(&image[..100 + ZIP.len() - 3]);
    let zip = find(&truncated, CandidateKind::Zip, 100);
    assert_eq!(zip.status, Status::Rejected);
    assert_eq!(
        zip.checks.last().unwrap().name,
        "zip_central_and_local_records"
    );
    let mut image = vec![0u8; 1000];
    image.extend_from_slice(PIHC);
    let report = scanned(&image);
    let pihc = find(&report, CandidateKind::Pihc, 1000);
    assert!(pihc.status.is_validated() && pihc.extent.is_none() && !pihc.carvable);
    assert!(
        report
            .next_steps
            .iter()
            .any(|s| s.code == StepCode::StructureWithoutDecoder)
    );
}

#[test]
fn header_only_and_decoderless_signatures_are_not_overstated() {
    let mut image = ubi();
    image.extend_from_slice(&xz());
    image.extend_from_slice(b"BZh91AY&SY");
    image.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]);
    image.extend_from_slice(b"sqsh");
    let report = scanned(&image);
    assert!(find(&report, CandidateKind::Ubi, 0).extent.is_none());
    assert!(find(&report, CandidateKind::Xz, 64).status.is_validated());
    for kind in [
        CandidateKind::Bzip2,
        CandidateKind::Zstd,
        CandidateKind::SquashFsBigEndian,
    ] {
        let candidate = report.candidates.iter().find(|c| c.kind == kind).unwrap();
        assert_eq!(
            (candidate.status, candidate.reason),
            (Status::SignatureOnly, Some(Reason::NoParserInThisBuild))
        );
    }
    assert!(carvable(&report).next().is_none());
}

#[test]
fn budgets_stop_work_and_mark_what_was_not_examined() {
    let mut image = Vec::new();
    for magic in [
        &b"hsqs"[..],
        b"\x7fELF",
        b"UBI#",
        &[0xd0, 0x0d, 0xfe, 0xed],
        &[0x27, 5, 0x19, 0x56],
    ] {
        for _ in 0..140 {
            image.extend_from_slice(magic);
            image.extend_from_slice(&[0; 4]);
        }
    }
    let report = scanned(&image);
    assert!(report.budget_exhausted);
    assert_eq!(report.hits_not_examined, 0);
    assert_eq!(
        report.validation_attempts as usize,
        BOUNDS.max_validation_attempts
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|c| c.reason == Some(Reason::AttemptBudgetExhausted)
                && c.status == Status::SignatureOnly)
    );
    assert!(
        report
            .next_steps
            .iter()
            .any(|s| s.code == StepCode::BudgetExhausted)
    );
    // Hits beyond the per-signature cap are counted and make the scan incomplete.
    let flood = [b'U', b'B', b'I', b'#'].repeat(BOUNDS.max_hits_per_signature + 100);
    let report = scanned(&flood);
    assert_eq!(report.hits_not_examined, 100);
    assert!(report.budget_exhausted);
    // A decompression bomb is cut at the entry limit and never validated.
    let bomb = gzip(&vec![0u8; 33 * 1024 * 1024]);
    assert!(bomb.len() < 1024 * 1024);
    let report = scanned(&bomb);
    let member = find(&report, CandidateKind::Gzip, 0);
    assert_eq!(
        (member.status, member.reason),
        (Status::SignatureOnly, Some(Reason::DecodeBudgetExhausted))
    );
    assert!(report.decoded_bytes <= BOUNDS.max_decoded_bytes);
}

#[test]
fn bad_gzip_trailers_and_uimage_crcs_are_charged_to_their_budgets() {
    let payload = [0x5a; 8192];
    let mut compressed = gzip(&payload);
    let crc = compressed.len() - 8;
    compressed[crc] ^= 1;
    let mut legacy = uimage(&payload);
    legacy[64] ^= 1;
    let report = scanned(&[compressed.as_slice(), &legacy].concat());
    assert_eq!(
        find(&report, CandidateKind::Gzip, 0).status,
        Status::Rejected
    );
    assert_eq!(
        find(&report, CandidateKind::UImage, compressed.len() as u64).status,
        Status::Rejected
    );
    assert_eq!(report.decoded_bytes, payload.len() as u64);
    assert!(report.validation_bytes >= (compressed.len() + payload.len()) as u64);
}

#[test]
fn zip_end_records_in_member_data_and_comment_do_not_shadow_the_archive() {
    let zip = include_bytes!("../../../../tests/fixtures/synthetic/zip-fake-eocd.zip");
    let image = [b"padding!".as_slice(), zip, b"suffix!"].concat();
    let report = scanned(&image);
    let candidate = find(&report, CandidateKind::Zip, 8);
    assert!(candidate.carvable);
    assert_eq!(candidate.extent, Some(zip.len() as u64));
    assert_eq!(report.validation_attempts, 1);
    assert!(!report.budget_exhausted);
    assert!(
        crate::input::structural_state(crate::input::InputKind::Zip, zip, &Limits::default())
            .is_ok()
    );
}

#[test]
fn fdt_requires_a_closed_root_and_validates_a_dtc_output() {
    let mut unclosed = fdt();
    unclosed[64..68].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        find(&scanned(&unclosed), CandidateKind::Fdt, 0).status,
        Status::Rejected
    );
    let real = include_bytes!("../../../../tests/fixtures/synthetic/synthetic-fdt.dtb");
    let report = scanned(real);
    let candidate = find(&report, CandidateKind::Fdt, 0);
    assert!(candidate.carvable, "{candidate:?}");
    assert_eq!(candidate.extent, Some(real.len() as u64));
}

#[test]
fn ubinize_erase_counter_header_is_validated_without_claiming_an_extent() {
    let bytes = include_bytes!("../../../../tests/fixtures/synthetic/synthetic-ubi-ec.bin");
    let report = scanned(bytes);
    let candidate = find(&report, CandidateKind::Ubi, 0);
    assert_eq!(candidate.status, Status::StructureValidated);
    assert_eq!(candidate.extent, None);
    assert!(!candidate.carvable);
}

#[test]
fn unknown_data_ends_in_a_diagnosis_without_candidates() {
    let mut state = [0u8; 32];
    let mut random = Vec::new();
    while random.len() < 256 * 1024 {
        state = sha2::Sha256::digest(state).into();
        random.extend_from_slice(&state);
    }
    let report_random = scanned(&random);
    assert_eq!(report_random.outcome, Outcome::NoSignatures);
    assert_eq!(
        report_random.next_steps[0].code,
        StepCode::HighEntropyNoSignature
    );
    let report_zero = scanned(&vec![0u8; 256 * 1024]);
    assert_eq!(
        report_zero.next_steps[0].code,
        StepCode::MostlyPaddingNoSignature
    );
    let text = scanned(b"just some plain text, no container here");
    assert_eq!(text.next_steps[0].code, StepCode::NoKnownSignature);
    assert!(scanned(&[]).candidates.is_empty());
}

#[test]
fn every_prefix_of_a_composite_image_is_scanned_without_panic() {
    let (image, _) = flash_image();
    for length in 0..=image.len() {
        let report = scanned(&image[..length]);
        for candidate in &report.candidates {
            if let Some(extent) = candidate.extent {
                assert!(candidate.offset + extent <= length as u64);
            }
        }
    }
}

#[test]
fn reports_are_identical_for_one_and_eight_workers_and_repeat_runs() {
    let (image, _) = flash_image();
    let scan_with = |threads| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| serde_json::to_vec(&scanned(&image)).unwrap())
    };
    let one = scan_with(1);
    assert_eq!(one, scan_with(8));
    assert_eq!(one, scan_with(1));
}

#[test]
fn an_expired_deadline_aborts_the_scan() {
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let budget = RunBudget::new(Limits::default(), Some(past));
    assert!(matches!(
        scan(b"PIHC", "00", &budget),
        Err(FwError::Limit(_))
    ));
}

#[test]
fn zip_with_an_undecodable_method_is_a_structure_validated_candidate() {
    // The records agree, so the structure and its extent are proven. Decoding the member is
    // a separate question that this build answers with "unsupported" at recovery time.
    let mut image = vec![0xff; 64];
    image.extend_from_slice(ZIP_BZIP2);
    image.extend_from_slice(&[0xff; 64]);
    let report = scanned(&image);
    let zip = find(&report, CandidateKind::Zip, 64);
    assert_eq!(zip.status, Status::StructureValidated);
    assert_eq!(zip.extent, Some(ZIP_BZIP2.len() as u64));
    assert!(zip.carvable);
}

#[test]
fn zip64_records_are_rejected_under_their_own_check() {
    let report = scanned(ZIP_ZIP64);
    let zip = find(&report, CandidateKind::Zip, 0);
    assert_eq!(zip.status, Status::Rejected);
    assert_eq!(
        zip.checks.last().map(|check| (check.name, check.passed)),
        Some(("zip_classic_32bit_records", false))
    );
    assert!(!zip.carvable && zip.extent.is_none());
}

#[test]
fn zip_stored_inside_a_zip_member_is_found_and_nested() {
    let report = scanned(ZIP_NESTED);
    let outer = find(&report, CandidateKind::Zip, 0);
    assert_eq!(outer.extent, Some(ZIP_NESTED.len() as u64));
    let at = ZIP_NESTED
        .windows(4)
        .enumerate()
        .skip(4)
        .find(|(_, window)| *window == b"PK\x03\x04")
        .map(|(at, _)| at as u64)
        .unwrap();
    let inner = find(&report, CandidateKind::Zip, at);
    assert!(inner.status.is_validated());
    assert_eq!(inner.nested_in, Some(outer.id));
    assert!(
        !inner.carvable,
        "a contained structure is reached through its parent"
    );
    // Member headers of a validated ZIP stay explained: the outer archive has one member.
    assert_eq!(outer.id, 0);
}

#[test]
fn real_squashfs_validates_and_a_shifted_copy_does_not() {
    let report = scanned(SQUASHFS_REAL);
    let image = find(&report, CandidateKind::SquashFs, 0);
    assert!(image.status.is_validated() && image.carvable);
    // Four extra bytes after the superblock move every table, as an interleaving container
    // would. The superblock fields stay plausible, but the tables no longer line up.
    let mut shifted = SQUASHFS_REAL[..100].to_vec();
    shifted.extend_from_slice(&[0xa5; 4]);
    shifted.extend_from_slice(&SQUASHFS_REAL[100..]);
    let used = shifted.len() as u64;
    shifted[40..48].copy_from_slice(&used.to_le_bytes());
    let report = scanned(&shifted);
    let image = find(&report, CandidateKind::SquashFs, 0);
    assert_eq!(image.status, Status::Rejected);
    assert_eq!(
        image.checks.last().map(|check| (check.name, check.passed)),
        Some(("squashfs_metadata_table_chains", false))
    );
    assert!(!image.carvable);
}
