//! Unknown, damaged and ambiguous input through the regular CLI entry points.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code may panic on failure.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const UIMAGE: &[u8] = include_bytes!("../../../fuzz/corpus/fuzz_squashfs/uimage-valid");
const GZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/stdlib-firmware.gz");
const ZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/central-valid.zip");
const PIHC: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/pihc-phase01.pkg");
const TAR_REPEATED: &[u8] =
    include_bytes!("../../../tests/fixtures/synthetic/tar-repeated-members.tar");
const ZIP_BZIP2: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/zip-bzip2-member.zip");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .args(args)
        .output()
        .expect("invoke nyra-fw")
}

fn success(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI stdout")
}

fn flash_like() -> Vec<u8> {
    let mut image = Vec::new();
    for part in [UIMAGE, GZIP, ZIP] {
        image.extend(std::iter::repeat_n(0xff, 100));
        image.extend_from_slice(part);
    }
    image.extend(std::iter::repeat_n(0xff, 64));
    image
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn scan_diagnoses_damaged_headers_instead_of_failing() {
    let temp = tempfile::tempdir().unwrap();
    let truncated = temp.path().join("truncated.pkg");
    fs::write(&truncated, &PIHC[..300]).unwrap();
    let report: serde_json::Value =
        serde_json::from_str(&success(&["scan", truncated.to_str().unwrap(), "--json"])).unwrap();
    assert_eq!(report["format"], "hichip-pihc");
    assert_eq!(report["structural_state"], "rejected");
    assert_eq!(report["rejection_class"], "structure_check_failed");
    assert_eq!(report["candidates"]["candidates"][0]["status"], "rejected");
    assert_eq!(
        report["candidates"]["candidates"][0]["checks"][0]["name"],
        "pihc_header_and_archive_offset"
    );
    let text = success(&["scan", truncated.to_str().unwrap()]);
    assert!(text.contains("rejected") && text.contains("failed=pihc_header_and_archive_offset"));

    let noise = temp.path().join("noise.bin");
    fs::write(&noise, b"no container in these bytes at all").unwrap();
    let text = success(&["scan", noise.to_str().unwrap()]);
    assert!(text.contains("NoSignatures") && text.contains("diagnosis ends here"));
}

#[test]
fn invalid_elf_prefix_does_not_hide_an_embedded_zip() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("flash.bin");
    fs::write(
        &input,
        [b"\x7fELF\xffopaque header".as_slice(), ZIP].concat(),
    )
    .unwrap();
    let input = input.to_str().unwrap();
    let workspace = temp.path().join("workspace");
    let target = workspace.to_str().unwrap();
    assert!(!run(&["analyze", input, "-o", target]).status.success());
    assert!(!workspace.exists());
    success(&["analyze", input, "-o", target, "--allow-partial"]);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(workspace.join("manifests/firmware.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["detected_format"], "elf-candidate-unverified");
    let artifact = manifest["artifacts"][0]["path"].as_str().unwrap();
    assert_eq!(fs::read(workspace.join(artifact)).unwrap(), ZIP);
    success(&["verify", target, "--replay", "--agent-ready"]);
}

#[test]
fn unknown_image_needs_the_partial_policy_and_then_replays_byte_identically() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("flash.bin");
    fs::write(&input, flash_like()).unwrap();
    let input = input.to_str().unwrap();

    let report: serde_json::Value =
        serde_json::from_str(&success(&["scan", input, "--json"])).unwrap();
    assert_eq!(report["format"], "unknown");
    assert_eq!(
        report["candidates"]["outcome"],
        "multiple_disjoint_structures"
    );

    let strict = temp.path().join("strict");
    let output = run(&["analyze", input, "-o", strict.to_str().unwrap()]);
    assert!(!output.status.success() && !strict.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-partial"));

    let (one, eight) = (temp.path().join("one"), temp.path().join("eight"));
    for (workspace, threads) in [(&one, "1"), (&eight, "8")] {
        success(&[
            "analyze",
            input,
            "-o",
            workspace.to_str().unwrap(),
            "--allow-partial",
            "--threads",
            threads,
        ]);
    }
    assert_eq!(tree(&one), tree(&eight));
    let replay = success(&["verify", eight.to_str().unwrap(), "--replay"]);
    assert!(replay.contains("REPLAY PASS: 3 artifacts"), "{replay}");
    let inspected = success(&["inspect", eight.to_str().unwrap()]);
    assert!(
        inspected.contains("Claude handoff: 4 artifacts"),
        "{inspected}"
    );
    let verified: serde_json::Value = serde_json::from_str(&success(&[
        "verify",
        eight.to_str().unwrap(),
        "--replay",
        "--json",
    ]))
    .unwrap();
    assert_eq!(verified["status"], "pass");
    assert_eq!(verified["replay_performed"], true);
    assert_eq!(verified["artifacts_verified"], 3);
    assert_eq!(verified["complete_firmware_established"], false);
    let summary: serde_json::Value =
        serde_json::from_str(&success(&["inspect", eight.to_str().unwrap(), "--json"])).unwrap();
    assert_eq!(summary["stage05"]["catalog_entries"], 4);

    // Altering a carve invalidates the immutable snapshot before replay is reached.
    let carve = fs::read_dir(eight.join("recovered/images/candidates"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = fs::read(&carve).unwrap();
    bytes[0] ^= 1;
    fs::write(&carve, bytes).unwrap();
    assert!(!run(&["verify", eight.to_str().unwrap()]).status.success());
}

#[test]
fn scan_reports_valid_but_unextractable_archives_as_unsupported() {
    let temp = tempfile::tempdir().unwrap();
    for (name, bytes) in [("repeated.tar", TAR_REPEATED), ("bzip2.zip", ZIP_BZIP2)] {
        let path = temp.path().join(name);
        fs::write(&path, bytes).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&success(&["scan", path.to_str().unwrap(), "--json"])).unwrap();
        assert_eq!(report["structural_state"], "rejected", "{name}");
        assert_eq!(report["rejection_class"], "unsupported", "{name}");
    }
    // The ZIP's records agree, so candidate discovery still proves its structure.
    let path = temp.path().join("bzip2.zip");
    let report: serde_json::Value =
        serde_json::from_str(&success(&["scan", path.to_str().unwrap(), "--json"])).unwrap();
    let first = &report["candidates"]["candidates"][0];
    assert_eq!(
        (first["kind"].as_str(), first["status"].as_str()),
        (Some("zip"), Some("structure_validated"))
    );
}
