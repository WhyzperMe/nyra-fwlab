//! End-to-end behavior of publication, verification and tamper detection.
use crate::{
    integrity,
    output::{json, write_new},
    publish::{publish_input, publish_tree},
    verify::verify_workspace,
};
use nyra_fw_core::{FirmwareManifest, FwError, Limits, budget::RunBudget, errors::io};
use nyra_fw_formats::pihc::RecoveryOptions;
use std::{fs, path::Path};

const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/pihc-phase01.pkg");
const GOLDEN: &str = "../../tests/fixtures/synthetic/phase01_golden.json";

fn publish_fixture(target: &Path) -> nyra_fw_core::Result<FirmwareManifest> {
    publish_input(
        target,
        Path::new("fixture.pkg"),
        SAMPLE,
        &RecoveryOptions::default(),
        &crate::stage02::Stage02Options::default(),
        false,
    )
    .map(|(manifest, _)| manifest)
}

#[test]
fn replay_rejects_plausible_but_false_provenance_in_rehashed_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("workspace");
    let mut firmware = publish_fixture(&target).unwrap();
    crate::verify_workspace_replay(&target).unwrap();
    firmware.artifacts[0].transformation = "raw-carve:unknown".into();
    fs::write(
        target.join("manifests/firmware.json"),
        json(&firmware).unwrap(),
    )
    .unwrap();
    fs::write(
        target.join("manifests/artifacts.json"),
        json(&firmware.artifacts).unwrap(),
    )
    .unwrap();
    fs::remove_file(target.join("manifests/workspace-integrity.json")).unwrap();
    integrity::write_snapshot(&target).unwrap();
    verify_workspace(&target).unwrap();
    assert!(
        matches!(crate::verify_workspace_replay(&target), Err(FwError::Verification(reason)) if reason.contains("provenance mismatch"))
    );
}

#[test]
fn disk_full_after_partial_write_discards_staging_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("workspace");
    let run = RunBudget::new(Limits::default(), None);
    let result = publish_tree(&target, &run, |stage| {
        write_new(stage, "original/partial", b"partial")?;
        Err(io(
            stage,
            std::io::Error::from(std::io::ErrorKind::StorageFull),
        ))
    });
    assert!(
        matches!(result, Err(FwError::Io { source, .. }) if source.kind() == std::io::ErrorKind::StorageFull)
    );
    assert!(!target.exists());
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn expired_publication_budget_does_not_start_writing() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("new-parent/workspace");
    let run = RunBudget::new(Limits::default(), Some(std::time::Instant::now()));
    let wrote = std::cell::Cell::new(false);
    let result = crate::publish::publish_directory(&target, &run, |_| {
        wrote.set(true);
        Ok(())
    });
    assert!(matches!(result, Err(FwError::Limit(_))));
    assert!(!wrote.get());
    assert!(!target.parent().unwrap().exists());
}

#[test]
fn invalid_publication_name_leaves_its_parent_absent() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("new-parent");
    let result = crate::publish::publish_directory(
        &parent.join(".."),
        &RunBudget::new(Limits::default(), None),
        |_| Ok(()),
    );
    assert!(matches!(result, Err(FwError::UnsafePath(_))));
    assert!(!parent.exists());
}

#[test]
fn publication_cross_checks_the_fresh_inventory_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = publish_fixture(&tmp.path().join("reference")).unwrap();
    let target = tmp.path().join("workspace");
    let run = RunBudget::new(Limits::default(), None);
    let result = publish_tree(&target, &run, |stage| {
        write_new(stage, "manifests/firmware.json", &json(&manifest)?)?;
        write_new(
            stage,
            &format!("original/{}", manifest.source.filename),
            b"wrong source bytes",
        )
    });
    assert!(matches!(result, Err(FwError::Verification(reason)) if reason.contains("original/")));
    assert!(!target.exists());
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
}

#[test]
fn verifies_stage05_workspace_without_stage06_records() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("stage05");
    let mut firmware = publish_fixture(&target).unwrap();
    firmware.producer = "nyra-fwlab/0.1.0".into();
    fs::write(
        target.join("manifests/firmware.json"),
        json(&firmware).unwrap(),
    )
    .unwrap();

    let analysis_path = target.join("manifests/analysis.json");
    let mut analysis: serde_json::Value =
        serde_json::from_slice(&fs::read(&analysis_path).unwrap()).unwrap();
    analysis
        .as_object_mut()
        .unwrap()
        .remove("decompiled_functions");
    let stage06_paths = [
        "manifests/stage06.json",
        "analysis/workspace/components.json",
        "analysis/workspace/outcomes.json",
        "analysis/archive/member-issues.json",
        // Workspaces from before the agent index existed have none.
        "analysis/workspace/agent-index.json",
    ];
    analysis["analysis_files"]
        .as_array_mut()
        .unwrap()
        .retain(|record| {
            !record["path"]
                .as_str()
                .is_some_and(|path| stage06_paths.contains(&path))
        });
    fs::write(analysis_path, json(&analysis).unwrap()).unwrap();
    for path in stage06_paths {
        fs::remove_file(target.join(path)).unwrap();
    }
    fs::remove_file(target.join("manifests/workspace-integrity.json")).unwrap();
    integrity::write_snapshot(&target).unwrap();
    let inspected = crate::inspect_all_verified(&target).unwrap();
    assert_eq!(inspected.stage05.source_sha256, firmware.source.sha256);
}

#[test]
fn publish_verify_and_reject_tampering() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let target = tmp.path().join("workspace");
    let manifest = publish_fixture(&target).expect("publish");
    assert_eq!(manifest.summary.recovered_crc_ok, 1);
    verify_workspace(&target).expect("verify");
    assert!(target.join("manifests/analysis.json").is_file());
    assert!(
        target
            .join("analysis/archive/central-directory.json")
            .is_file()
    );
    assert!(target.join("analysis/lens/function-index.json").is_file());
    assert!(target.join("manifests/stage03.json").is_file());
    assert!(target.join("manifests/workspace-integrity.json").is_file());
    assert!(
        target
            .join("analysis/stage03/dependency-resolution.json")
            .is_file()
    );
    assert!(
        target
            .join("analysis/hardware/stage04-inventory.json")
            .is_file()
    );
    assert!(
        target
            .join("analysis/hardware/lens-worklist.json")
            .is_file()
    );
    assert!(target.join("manifests/stage05.json").is_file());
    assert!(
        target
            .join("analysis/workspace/artifact-catalog.json")
            .is_file()
    );
    assert!(target.join("analysis/workspace/detection.json").is_file());
    assert!(target.join("analysis/workspace/task-plan.json").is_file());
    let inspection = crate::inspect_all_verified(&target).expect("verified inspection");
    let handoff = inspection.stage05;
    assert_eq!(handoff.catalog_entries, manifest.artifacts.len() + 1);
    assert!(handoff.ready_tasks > 0);
    let prompt = fs::read_to_string(target.join("CLAUDE.md")).expect("generated instructions");
    assert!(prompt.contains("untrusted DATA"));
    assert!(prompt.contains("reconstruction/"));
    let stage04 = inspection.stage04;
    assert_eq!(stage04.schema_version, 1);
    assert_eq!(stage04.rootfs_state, "not_extracted");
    let stage03 = inspection.stage03;
    assert_eq!(stage03.analyzed_elfs, 0);
    let stage05_analysis = target.join("analysis/workspace/detection.json");
    let stage05_original = fs::read(&stage05_analysis).expect("Stage 05 original");
    fs::write(&stage05_analysis, b"{}").expect("tamper Stage 05");
    assert!(verify_workspace(&target).is_err());
    fs::write(&stage05_analysis, stage05_original).expect("restore Stage 05");
    verify_workspace(&target).expect("Stage 05 integrity repaired");
    let stage03_analysis = target.join("analysis/stage03/prioritized-binaries.json");
    let original_index = fs::read(&stage03_analysis).expect("triage bytes");
    fs::write(&stage03_analysis, b"replaced").expect("tamper stage03");
    assert!(verify_workspace(&target).is_err());
    fs::write(&stage03_analysis, original_index).expect("restore stage03");
    verify_workspace(&target).expect("verify restored stage03");
    let stage04_path = target.join("analysis/hardware/stage04-inventory.json");
    let stage04_bytes = fs::read(&stage04_path).expect("stage04 original");
    fs::write(&stage04_path, b"{}").expect("tamper stage04");
    assert!(verify_workspace(&target).is_err());
    fs::write(&stage04_path, stage04_bytes).expect("restore stage04");
    verify_workspace(&target).expect("verify restored stage04");
    let analyzed = target.join("analysis/archive/central-directory.json");
    let audit_copy = fs::read(&analyzed).expect("audit bytes");
    fs::write(&analyzed, b"corrupted").expect("tamper analysis");
    assert!(verify_workspace(&target).is_err());
    fs::write(&analyzed, audit_copy).expect("restore audit");
    verify_workspace(&target).expect("verify repaired");
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    assert_eq!(
        crate::golden::compare_phase01_golden(&verify_workspace(&target).unwrap(), &golden)
            .expect("golden"),
        2
    );
    assert!(publish_fixture(&target).is_err());
    let member = target.join("recovered/update/mnt/mtd/ipc/test_motor.dat");
    let mut bytes = fs::read(&member).expect("read");
    bytes[0] ^= 0xaa;
    fs::write(&member, bytes).expect("tamper test");
    assert!(verify_workspace(&target).is_err());
}
