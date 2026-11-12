#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code may panic on failure.
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("read workspace directory") {
        let entry = entry.expect("read workspace entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("read workspace entry type");
        assert!(
            !file_type.is_symlink(),
            "workspace contains symlink: {path:?}"
        );
        if file_type.is_dir() {
            collect_files(root, &path, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("workspace entry is under its root")
                .to_path_buf();
            files.insert(relative, fs::read(path).expect("read workspace file"));
        }
    }
}

fn workspace_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    collect_files(root, root, &mut files);
    files
}

fn analyze(firmware: &Path, workspace: &Path, threads: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .arg("analyze")
        .arg(firmware)
        .arg("-o")
        .arg(workspace)
        .args(["--threads", threads])
        .output()
        .expect("invoke nyra-fw");
    assert!(
        output.status.success(),
        "analyze with {threads} workers failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn offline_pihc_workspace_bytes_are_identical_with_one_and_eight_workers() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/synthetic/pihc-phase01.pkg");
    let temp = tempfile::tempdir().expect("create temporary directory");
    let one_worker = temp.path().join("one-worker");
    let eight_workers = temp.path().join("eight-workers");

    analyze(&fixture, &one_worker, "1");
    analyze(&fixture, &eight_workers, "8");

    let one_worker_files = workspace_files(&one_worker);
    let eight_worker_files = workspace_files(&eight_workers);
    assert_eq!(
        one_worker_files, eight_worker_files,
        "offline PIHC workspace files must have identical paths and bytes regardless of worker count"
    );
}

#[test]
fn failed_optional_squashfs_tool_requires_explicit_partial_policy() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/synthetic/pihc-phase01.pkg");
    let temp = tempfile::tempdir().expect("create temporary directory");
    let strict_workspace = temp.path().join("strict-workspace");
    let partial_workspace = temp.path().join("partial-workspace");

    let strict = Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .arg("analyze")
        .arg(&fixture)
        .arg("-o")
        .arg(&strict_workspace)
        .args(["--extract-filesystems"])
        .output()
        .expect("invoke strict filesystem analysis");
    assert!(
        !strict.status.success(),
        "strict optional-tool failure should fail the analysis"
    );
    assert!(
        !strict_workspace.exists(),
        "strict optional-tool failure must not publish a workspace"
    );

    let partial = Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .arg("analyze")
        .arg(&fixture)
        .arg("-o")
        .arg(&partial_workspace)
        .args(["--extract-filesystems", "--allow-partial-tools"])
        .output()
        .expect("invoke partial filesystem analysis");
    assert!(
        partial.status.success(),
        "explicit partial-tool policy should publish the recovery workspace: {}",
        String::from_utf8_lossy(&partial.stderr)
    );

    let outcomes: serde_json::Value = serde_json::from_slice(
        &fs::read(partial_workspace.join("analysis/workspace/outcomes.json"))
            .expect("read optional-tool outcomes"),
    )
    .expect("parse optional-tool outcomes");
    assert_eq!(outcomes["squashfs"]["state"], "failed");

    let verified = Command::new(env!("CARGO_BIN_EXE_nyra-fw"))
        .arg("verify")
        .arg(&partial_workspace)
        .output()
        .expect("verify partial workspace");
    assert!(
        verified.status.success(),
        "published partial workspace should verify: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}
