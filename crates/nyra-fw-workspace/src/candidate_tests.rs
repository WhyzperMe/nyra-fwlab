//! End-to-end behavior for unknown, damaged and ambiguous input.
use crate::{integrity, output, publish as publishing, replay, verify};
use nyra_fw_core::{ArtifactKind, FwError, Limits, Verification, sha256_hex};
use nyra_fw_formats::pihc::{KeyMode, RecoveryOptions};
use std::{fs, path::Path};

const UIMAGE: &[u8] = include_bytes!("../../../fuzz/corpus/fuzz_squashfs/uimage-valid");
const GZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/stdlib-firmware.gz");
const ZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/central-valid.zip");

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

fn options(require_all: bool) -> RecoveryOptions {
    RecoveryOptions {
        limits: Limits::default(),
        key_mode: KeyMode::Probe,
        require_all,
    }
}

pub(crate) fn publish(
    target: &Path,
    raw: &[u8],
    require_all: bool,
) -> nyra_fw_core::Result<nyra_fw_core::FirmwareManifest> {
    publishing::publish_input(
        target,
        Path::new("flash.bin"),
        raw,
        &options(require_all),
        &Default::default(),
        false,
    )
    .map(|(manifest, _)| manifest)
}

/// Padding, a uImage, a SquashFS superblock, a gzip member and a ZIP archive.
pub(crate) fn flash_like() -> (Vec<u8>, Vec<(u64, usize)>) {
    let mut image = Vec::new();
    let mut parts = Vec::new();
    for (index, part) in [UIMAGE, &squashfs(200), GZIP, ZIP].into_iter().enumerate() {
        image.extend(std::iter::repeat_n(0xff, 100 + index * 13));
        parts.push((image.len() as u64, part.len()));
        image.extend_from_slice(part);
    }
    image.extend(std::iter::repeat_n(0xff, 64));
    (image, parts)
}

fn rehash(target: &Path) {
    fs::remove_file(target.join("manifests/workspace-integrity.json")).unwrap();
    integrity::write_snapshot(target).unwrap();
}

#[test]
fn component_graph_keeps_decoded_gzip_coordinates_separate() {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&[42; 17]).unwrap();
    encoder.write_all(&squashfs(200)).unwrap();
    let gzip = encoder.finish().unwrap();
    let raw = [&[255; 64][..], gzip.as_slice()].concat();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    publish(&root, &raw, false).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(crate::component_graph::PATH)).unwrap())
            .unwrap();
    let nodes = report["candidates"].as_array().unwrap();
    let parent = nodes.iter().find(|node| node["format"] == "gzip").unwrap();
    assert_eq!(parent["address"]["space"], "original");
    assert_eq!(parent["offset"], 64);
    let child = nodes
        .iter()
        .find(|node| node["format"] == "squashfs")
        .unwrap();
    assert_eq!(child["address"]["space"], "decoded_gzip");
    assert_eq!(child["address"]["container_candidate"], parent["id"]);
    assert_eq!(child["offset"], 17);
    assert_eq!(child["carvable"], false);
    assert_eq!(report["artifacts"][0]["candidate"], parent["id"]);
    assert_eq!(report["root_filesystem_candidates"][0]["id"], child["id"]);
    crate::verify_workspace_replay(&root).unwrap();
}

#[test]
fn replay_checks_archive_and_component_reports_even_after_snapshot_rehash() {
    let temp = tempfile::tempdir().unwrap();
    for (name, report, claim) in [
        ("zip", crate::ARCHIVE_STRUCTURE_PATH, "archive_bytes"),
        ("graph", crate::component_graph::PATH, "source_path"),
    ] {
        let root = temp.path().join(name);
        let manifest = publish(&root, ZIP, true).unwrap();
        let path = root.join(report);
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data[claim] = "tampered".into();
        fs::write(path, output::json(&data).unwrap()).unwrap();
        rehash(&root);
        let inventory = integrity::verify_snapshot(&root).unwrap();
        assert!(matches!(
            replay::replay_verified(&root, &manifest, &inventory),
            Err(FwError::Verification(reason)) if reason.contains(report)
        ));
    }
}

#[test]
fn recognized_uimage_does_not_hide_a_structure_after_its_payload() {
    let raw = [UIMAGE, &[255; 128], ZIP].concat();
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    let manifest = publish(&workspace, &raw, true).unwrap();
    assert_eq!(manifest.detected_format, "uimage");
    assert_eq!(manifest.artifacts.len(), 1);
    let map: serde_json::Value =
        serde_json::from_slice(&fs::read(workspace.join(crate::byte_map::PATH)).unwrap()).unwrap();
    assert!(map["claims"].as_array().unwrap().iter().any(|claim| {
        claim["type"] == "candidate"
            && claim["kind"] == "zip"
            && claim["start"] == UIMAGE.len() + 128
            && claim["end"] == raw.len()
    }));
    crate::verify_agent_ready(&workspace, true).unwrap();
}

#[test]
fn unknown_flash_image_is_rejected_by_default_and_carved_under_partial_policy() {
    let (image, parts) = flash_like();
    let temp = tempfile::tempdir().unwrap();
    let strict = temp.path().join("strict");
    let error = publish(&strict, &image, true).unwrap_err();
    assert!(
        matches!(&error, FwError::Unsupported(reason) if reason.contains("candidate scan")),
        "{error}"
    );
    assert!(!strict.exists());

    let target = temp.path().join("partial");
    let manifest = publish(&target, &image, false).unwrap();
    assert_eq!(manifest.detected_format, "unknown-unverified");
    assert_eq!(manifest.artifacts.len(), parts.len());
    for (artifact, (offset, length)) in manifest.artifacts.iter().zip(&parts) {
        let range = *offset as usize..*offset as usize + length;
        assert_eq!(artifact.source_start, *offset);
        assert_eq!(artifact.source_length, *length as u64);
        assert_eq!(artifact.sha256, sha256_hex(&image[range.clone()]));
        assert_eq!(artifact.parent_sha256, manifest.source.sha256);
        assert_eq!(
            fs::read(target.join(&artifact.path)).unwrap(),
            &image[range]
        );
        assert!(artifact.path.starts_with("recovered/images/candidates/"));
    }
    let verification: Vec<_> = manifest.artifacts.iter().map(|a| a.verification).collect();
    assert_eq!(
        verification,
        [
            Verification::OriginalCrc32,
            Verification::HeaderValidated,
            Verification::OriginalCrc32,
            Verification::HeaderValidated
        ]
    );
    assert_eq!(manifest.artifacts[1].kind, ArtifactKind::SquashFsImage);
    verify::verify_workspace(&target).unwrap();
    crate::verify_workspace_replay(&target).unwrap();

    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/candidates.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["outcome"], "multiple_disjoint_structures");
    assert_eq!(report["source_sha256"], manifest.source.sha256.as_str());
    let handoff = crate::inspect_all_verified(&target).unwrap().stage05;
    assert_eq!(handoff.catalog_entries, manifest.artifacts.len() + 1);
    assert!(handoff.ready_tasks > 0);
    let plan: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/task-plan.json")).unwrap(),
    )
    .unwrap();
    let task = plan
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["id"] == "triage-candidates")
        .expect("candidate triage task");
    assert_eq!(task["state"], "ready");
    let claude = fs::read_to_string(target.join("CLAUDE.md")).unwrap();
    assert!(claude.contains("analysis/workspace/candidates.json"));
}

#[test]
fn replay_rejects_false_carve_provenance_in_a_rehashed_preserved_workspace() {
    let (image, _) = flash_like();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("workspace");
    let mut manifest = publish(&target, &image, false).unwrap();
    crate::verify_workspace_replay(&target).unwrap();
    manifest.artifacts[1].transformation = "raw-carve:candidate-elf".into();
    fs::write(
        target.join("manifests/firmware.json"),
        output::json(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(
        target.join("manifests/artifacts.json"),
        output::json(&manifest.artifacts).unwrap(),
    )
    .unwrap();
    rehash(&target);
    verify::verify_workspace(&target).unwrap();
    assert!(
        matches!(crate::verify_workspace_replay(&target), Err(FwError::Verification(reason)) if reason.contains("provenance mismatch")),
    );
}

#[test]
fn replay_rejects_a_candidate_report_that_contradicts_the_source() {
    let (image, _) = flash_like();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("workspace");
    let manifest = publish(&target, &image, false).unwrap();
    let report_path = target.join("analysis/workspace/candidates.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    report["candidates"][0]["offset"] = 7.into();
    // The comparison runs on its own: the report is not required to be reachable
    // through a consistent snapshot to be rejected against the source bytes.
    fs::write(&report_path, output::json(&report).unwrap()).unwrap();
    let result = replay::verify_preserved_for_test(&target, &image, &manifest);
    assert!(
        matches!(result, Err(FwError::Verification(reason)) if reason.contains("candidate report differs")),
    );
}

#[test]
fn input_without_structure_ends_in_a_diagnosis_and_replays_with_no_artifacts() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let noise: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect();
    let temp = tempfile::tempdir().unwrap();
    assert!(publish(&temp.path().join("strict"), &noise, true).is_err());
    let target = temp.path().join("partial");
    let manifest = publish(&target, &noise, false).unwrap();
    assert!(manifest.artifacts.is_empty());
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/candidates.json")).unwrap(),
    )
    .unwrap();
    let step = report["next_steps"][0]["code"].as_str().unwrap();
    assert!(
        matches!(step, "high_entropy_no_signature" | "no_known_signature"),
        "{step}"
    );
    verify::verify_workspace(&target).unwrap();
    crate::verify_workspace_replay(&target).unwrap();
}

#[test]
fn valid_gzip_beyond_the_decode_limit_is_preserved_only_for_partial_recovery() {
    use std::io::Write;

    // 34 MiB of zeros compress to a few dozen kilobytes but exceed the 32 MiB member limit.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&vec![0u8; 34 * 1024 * 1024]).unwrap();
    let gzip = encoder.finish().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let strict = temp.path().join("strict");
    assert!(matches!(
        publish(&strict, &gzip, true),
        Err(FwError::Limit(_))
    ));
    assert!(!strict.exists(), "a refused run must publish nothing");
    let target = temp.path().join("partial");
    let manifest = publish(&target, &gzip, false).unwrap();
    assert!(manifest.artifacts.is_empty());
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/candidates.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["budget_exhausted"], true);
    assert_eq!(report["candidates"][0]["reason"], "decode_budget_exhausted");
    verify::verify_workspace(&target).unwrap();
    crate::verify_workspace_replay(&target).unwrap();
}

#[test]
fn overlapping_structures_are_reported_but_not_carved() {
    // The second uImage starts inside the first one's payload and ends after it. Both
    // checksums verify. Leading bytes keep the input from being recognized as a plain uImage.
    let uimage = |payload: &[u8]| {
        let mut header = vec![0u8; 64];
        header[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
        header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let mut crc = flate2::Crc::new();
        crc.update(payload);
        header[24..28].copy_from_slice(&crc.sum().to_be_bytes());
        header[28..32].copy_from_slice(&[5, 2, 2, 0]);
        let mut crc = flate2::Crc::new();
        crc.update(&header);
        header[4..8].copy_from_slice(&crc.sum().to_be_bytes());
        [header, payload.to_vec()].concat()
    };
    let image_b = uimage(&[0x5a; 256]);
    let mut payload_a = vec![0xa5; 64];
    payload_a.extend_from_slice(&image_b[..image_b.len() / 2]);
    let image_a = uimage(&payload_a);
    let mut image = vec![0xff; 8];
    image.extend_from_slice(&image_a[..128]);
    image.extend_from_slice(&image_b);
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("workspace");
    let manifest = publish(&target, &image, false).unwrap();
    assert!(manifest.artifacts.is_empty());
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/candidates.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["outcome"], "ambiguous");
    assert!(
        report["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["code"] == "resolve_overlapping_candidates")
    );
    crate::verify_workspace_replay(&target).unwrap();
}

#[test]
fn truncated_known_container_keeps_the_source_and_reports_the_failed_check() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("workspace");
    let truncated = &ZIP[..ZIP.len() - 5];
    let manifest = publish(&target, truncated, false).unwrap();
    assert_eq!(manifest.detected_format, "zip-unverified");
    assert!(manifest.artifacts.is_empty());
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(target.join("analysis/workspace/candidates.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["candidates"][0]["status"], "rejected");
    assert_eq!(
        report["candidates"][0]["checks"][0]["name"],
        "zip_central_and_local_records"
    );
    crate::verify_workspace_replay(&target).unwrap();
}

#[test]
fn preserved_workspace_from_before_candidate_reports_still_verifies() {
    // A 0.6.2 workspace of an unrecognized input has no candidate report. Remove the
    // report and its index record to reproduce that layout, then rehash.
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("workspace");
    let mut manifest = publish(&target, b"legacy input with no known container", false).unwrap();
    assert_eq!(manifest.detected_format, "unknown-unverified");
    fs::remove_file(target.join("analysis/workspace/candidates.json")).unwrap();
    let path = target.join("manifests/analysis.json");
    let mut analysis: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    analysis["analysis_files"]
        .as_array_mut()
        .unwrap()
        .retain(|record| {
            record["path"] != "analysis/workspace/candidates.json"
                && record["path"] != "analysis/workspace/agent-index.json"
        });
    fs::remove_file(target.join("analysis/workspace/agent-index.json")).unwrap();
    manifest.producer = "nyra-fwlab/0.6.2".into();
    fs::write(
        target.join("manifests/firmware.json"),
        output::json(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(&path, output::json(&analysis).unwrap()).unwrap();
    rehash(&target);
    verify::verify_workspace(&target).unwrap();
    crate::inspect_all_verified(&target).unwrap();
    // Replay cannot re-derive what was never recorded and says so.
    assert!(
        matches!(crate::verify_workspace_replay(&target), Err(FwError::Verification(reason)) if reason.contains("lacks a candidate report"))
    );
}

#[test]
fn explicit_candidate_selection_replays_and_is_part_of_the_resume_key() {
    let (image, parts) = flash_like();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("selected");
    let analysis = Default::default();
    let input = Path::new("flash.bin");
    let options = options(false);
    let report = nyra_fw_formats::candidates::scan(
        &image,
        &sha256_hex(&image),
        &nyra_fw_core::budget::RunBudget::new(Limits::default(), None),
    )
    .unwrap();
    let id = report
        .candidates
        .iter()
        .find(|candidate| candidate.carvable && candidate.offset == parts[1].0)
        .unwrap()
        .id;
    let publish = |target: &Path, candidate| {
        publishing::publish_input_with_policy(
            target,
            input,
            &image,
            &options,
            &analysis,
            true,
            &publishing::PipelinePolicy {
                candidate: Some(candidate),
                ..Default::default()
            },
        )
    };
    let (manifest, reused) = publish(&target, id).unwrap();
    assert!(!reused);
    assert_eq!(manifest.artifacts.len(), 1);
    assert_eq!(manifest.artifacts[0].source_start, parts[1].0);
    assert_eq!(manifest.artifacts[0].source_length, parts[1].1 as u64);
    crate::verify_agent_ready(&target, true).unwrap();
    assert!(publish(&target, id).unwrap().1);
    assert!(publish(&target, id + 1).is_err());
    let invalid = temp.path().join("invalid");
    assert!(publish(&invalid, u32::MAX).is_err());
    assert!(!invalid.exists());
}

#[test]
fn replay_accepts_preserved_squashfs_and_snapshot_refuses_a_claimed_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("squashfs");
    let image = squashfs(256);
    let mut manifest = publish(&target, &image, true).unwrap();
    assert_eq!(manifest.detected_format, "squashfs");
    assert!(manifest.artifacts.is_empty());
    crate::verify_workspace_replay(&target).unwrap();

    // A rehashed workspace that claims a carve the source cannot produce is refused.
    manifest.artifacts.push(nyra_fw_core::Artifact {
        path: "recovered/images/claimed.bin".into(),
        kind: ArtifactKind::FirmwareImage,
        size: 0,
        sha256: sha256_hex(b""),
        verification: Verification::HeaderValidated,
        source_start: 0,
        source_length: 0,
        transformation: "raw-carve:claimed".into(),
        parent_sha256: manifest.source.sha256.clone(),
    });
    fs::write(target.join("recovered/images/claimed.bin"), b"").unwrap();
    fs::write(
        target.join("manifests/firmware.json"),
        output::json(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(
        target.join("manifests/artifacts.json"),
        output::json(&manifest.artifacts).unwrap(),
    )
    .unwrap();
    rehash(&target);
    // The Stage 05 catalog no longer matches, so the snapshot-level checks already refuse it.
    assert!(verify::verify_workspace(&target).is_err());
}
