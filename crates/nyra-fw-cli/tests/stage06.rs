#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code may panic on failure.
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI stdout")
}

#[test]
fn a_closed_stdout_pipe_exits_cleanly_without_a_panic() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("pipe.bin");
    // More report bytes than a pipe can buffer, so this exercises a real write
    // failure even if the child starts writing before the read handle is dropped.
    let mut bytes = Vec::new();
    for _ in 0..600 {
        bytes.extend_from_slice(b"\x7fELF");
        bytes.extend_from_slice(&[0; 124]);
    }
    fs::write(&input, bytes).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .arg("scan")
        .arg(&input)
        .arg("--candidates")
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn zip_dispatch_and_resume_verify_options_and_content() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/synthetic/central-valid.zip");
    let fixture = fixture.to_str().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("work");
    let workspace = target.to_str().unwrap();
    let report: serde_json::Value =
        serde_json::from_str(&success(&["scan", fixture, "--json"])).unwrap();
    assert_eq!(report["format"], "zip");
    success(&["analyze", fixture, "-o", workspace, "--threads", "1"]);
    assert!(
        success(&[
            "analyze",
            fixture,
            "-o",
            workspace,
            "--threads",
            "2",
            "--resume"
        ])
        .contains("Reused verified")
    );
    assert!(
        !run(&[
            "analyze",
            fixture,
            "-o",
            workspace,
            "--allow-partial",
            "--resume"
        ])
        .status
        .success()
    );
    fs::write(target.join("CLAUDE.md"), "tampered").unwrap();
    assert!(
        !run(&["analyze", fixture, "-o", workspace, "--resume"])
            .status
            .success()
    );
}

#[test]
fn scan_and_replay_share_zip_structure_without_claiming_crc_success() {
    let mut bytes = include_bytes!("../../../tests/fixtures/synthetic/central-valid.zip").to_vec();
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("crc.zip");
    let target = temp.path().join("work");
    let (input_path, workspace) = (input.to_str().unwrap(), target.to_str().unwrap());
    fs::write(&input, &bytes).unwrap();
    let scan: serde_json::Value =
        serde_json::from_str(&success(&["scan", input_path, "--json"])).unwrap();
    let finding = &scan["archive"];
    let member = &finding["regular_members"][0];
    assert!(member["declared_payload_crc32"].is_u64());
    bytes[member["payload_offset"].as_u64().unwrap() as usize] ^= 0x40;
    fs::write(&input, bytes).unwrap();
    let corrupt: serde_json::Value =
        serde_json::from_str(&success(&["scan", input_path, "--json"])).unwrap();
    assert_eq!(corrupt["structural_state"], scan["structural_state"]);
    assert_ne!(corrupt["sha256"], scan["sha256"]);
    assert!(
        !run(&["analyze", input_path, "-o", workspace])
            .status
            .success()
    );
    assert!(!target.exists());
    let manifest: serde_json::Value = serde_json::from_str(&success(&[
        "analyze",
        input_path,
        "-o",
        workspace,
        "--allow-partial",
        "--json",
    ]))
    .unwrap();
    assert_eq!(manifest["summary"]["original_crc_ok"], 0);
    assert_eq!(manifest["summary"]["failed_entries"], 1);
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join("analysis/archive/structure.json")).unwrap())
            .unwrap();
    assert_eq!(stored, corrupt["archive"]);
    success(&["verify", workspace, "--replay", "--agent-ready"]);
}

#[test]
fn timings_leave_stdout_and_workspace_deterministic() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/synthetic/central-valid.zip");
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("work");
    let plain = temp.path().join("plain");
    let fixture = fixture.to_str().unwrap();
    let workspace = target.to_str().unwrap();
    let plain_stdout = success(&[
        "analyze",
        fixture,
        "-o",
        plain.to_str().unwrap(),
        "--json",
        "--threads",
        "1",
    ]);
    for (flags, outcome, phase) in [
        (&[][..], "published", "archive_index"),
        (&["--resume"][..], "reused", "verify_reuse"),
    ] {
        let args = [
            "analyze",
            fixture,
            "-o",
            workspace,
            "--json",
            "--threads",
            "1",
            "--timings",
        ];
        let output = run(&[args.as_slice(), flags].concat());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, plain_stdout.as_bytes());
        let timings: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(timings["schema_version"], 1);
        assert_eq!(timings["outcome"], outcome);
        assert_eq!(timings["workers"], 1);
        assert!(timings["elapsed_ns"].is_u64());
        let phases = timings["phases"].as_array().unwrap();
        for required in ["input_read", "input_hash", phase] {
            assert!(
                phases
                    .iter()
                    .any(|sample| sample["phase"] == required && sample["calls"] == 1)
            );
        }
    }
    let snapshot = "manifests/workspace-integrity.json";
    assert_eq!(
        fs::read(target.join(snapshot)).unwrap(),
        fs::read(plain.join(snapshot)).unwrap()
    );
}

#[test]
fn corrupt_container_is_preserved_only_with_partial_policy() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bad.pkg");
    let target = temp.path().join("work");
    fs::write(&input, b"PIHC truncated").unwrap();
    let (input, workspace) = (input.to_str().unwrap(), target.to_str().unwrap());
    assert!(!run(&["analyze", input, "-o", workspace]).status.success());
    assert!(!target.exists());
    success(&["analyze", input, "-o", workspace, "--allow-partial"]);
    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join("manifests/stage06.json")).unwrap()).unwrap();
    assert_eq!(status["recovery_state"], "partial");
    assert_eq!(status["full_flash_verified"], false);
    success(&["verify", workspace]);
}

#[test]
fn concurrent_publications_preserve_the_winning_workspace() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/synthetic/central-valid.zip");
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("work");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nyra-fw"));
    command
        .arg("analyze")
        .arg(fixture)
        .arg("-o")
        .arg(&target)
        .args(["--threads", "1"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut first = command.spawn().unwrap();
    let mut second = command.spawn().unwrap();
    assert_ne!(
        first.wait().unwrap().success(),
        second.wait().unwrap().success()
    );
    success(&["verify", target.to_str().unwrap()]);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn uimage_payload_is_carved_at_the_verified_source_offset() {
    let raw = include_bytes!("../../../fuzz/corpus/fuzz_squashfs/uimage-valid");
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("uimage");
    let workspace = temp.path().join("work");
    fs::write(&input, raw).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&success(&[
        "analyze",
        input.to_str().unwrap(),
        "-o",
        workspace.to_str().unwrap(),
        "--json",
    ]))
    .unwrap();
    assert_eq!(manifest["detected_format"], "uimage");
    assert_eq!(manifest["artifacts"][0]["source_start"], 64);
    assert_eq!(manifest["artifacts"][0]["verification"], "original_crc32");
    assert_eq!(
        fs::read(workspace.join("recovered/images/uimage-payload.bin")).unwrap(),
        &raw[64..]
    );
}
