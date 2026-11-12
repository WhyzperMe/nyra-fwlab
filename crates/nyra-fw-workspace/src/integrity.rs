//! SHA-256 inventory of immutable workspace files.
use crate::{
    files,
    output::{json, write_new},
};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use nyra_fw_core::{FwError, Result, budget::RunBudget, errors::io, path::is_safe_relative};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

const SNAPSHOT: &str = "manifests/workspace-integrity.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileRecord {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    schema_version: u32,
    algorithm: String,
    excludes: Vec<String>,
    files: Vec<FileRecord>,
}

pub(crate) struct Inventory(Vec<FileRecord>);

impl Inventory {
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn read_checked(&self, root: &Path, path: &str, max: u64) -> Result<Vec<u8>> {
        let bytes = files::read_relative(root, path, max)?;
        self.check(path, bytes.len() as u64, &nyra_fw_core::sha256_hex(&bytes))?;
        Ok(bytes)
    }

    pub(crate) fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        root: &Path,
        path: &str,
        max: u64,
    ) -> Result<T> {
        let bytes = self.read_checked(root, path, max)?;
        serde_json::from_slice(&bytes).map_err(Into::into)
    }

    pub(crate) fn contains(&self, path: &str) -> bool {
        self.0
            .binary_search_by(|record| record.path.as_str().cmp(path))
            .is_ok()
    }

    pub(crate) fn check(&self, path: &str, bytes: u64, sha256: &str) -> Result<()> {
        if !is_safe_relative(path) {
            return Err(FwError::UnsafePath(path.into()));
        }
        if self
            .0
            .binary_search_by(|record| record.path.as_str().cmp(path))
            .ok()
            .is_some_and(|index| self.0[index].bytes == bytes && self.0[index].sha256 == sha256)
        {
            return Ok(());
        }
        Err(FwError::Verification(format!(
            "content or inventory mismatch: {path}"
        )))
    }
}

fn inventory(root: &Path, run: Option<&RunBudget>) -> Result<Vec<FileRecord>> {
    struct Walker<'a> {
        entries: Vec<FileRecord>,
        visited: usize,
        remaining: u64,
        run: Option<&'a RunBudget>,
    }
    impl Walker<'_> {
        fn hash_batch(&mut self, dir: &Dir, pending: &mut Vec<String>) -> Result<()> {
            let remaining = AtomicU64::new(self.remaining);
            let hash = |path: String| {
                if let Some(run) = self.run {
                    run.checkpoint()?;
                }
                let name = path.rsplit('/').next().unwrap_or_default();
                let file = files::open_regular(dir, Path::new(name))?;
                remaining
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |bytes| {
                        bytes.checked_sub(file.len())
                    })
                    .map_err(|_| {
                        FwError::Limit("workspace integrity byte budget exceeded".into())
                    })?;
                let max = if path.starts_with("original/") || path.starts_with("recovered/images/")
                {
                    nyra_fw_core::Limits::default().max_input_bytes
                } else {
                    files::REPORT_BYTES
                };
                let (bytes, sha256) = files::digest(file, Path::new(&path), max)?;
                Ok(FileRecord {
                    path,
                    bytes,
                    sha256,
                })
            };
            if self.run.is_some() && pending.len() > 1 {
                let records: Result<Vec<_>> = pending.par_drain(..).map(hash).collect();
                self.entries.extend(records?);
            } else {
                for path in pending.drain(..) {
                    self.entries.push(hash(path)?);
                }
            }
            self.remaining = remaining.into_inner();
            Ok(())
        }

        fn walk(&mut self, dir: &Dir, prefix: &str) -> Result<()> {
            let mut pending = Vec::new();
            for entry in dir.entries().map_err(|e| io(Path::new(prefix), e))? {
                let entry = entry.map_err(|e| io(Path::new(prefix), e))?;
                self.visited += 1;
                if self.visited > files::WORKSPACE_ENTRIES {
                    return Err(FwError::Limit(
                        "workspace contains too many filesystem nodes".into(),
                    ));
                }
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| FwError::UnsafePath("non-UTF-8 workspace path".into()))?;
                if name.contains('/') || !is_safe_relative(name) {
                    return Err(FwError::UnsafePath(name.into()));
                }
                let path = format!("{prefix}{name}");
                if !is_safe_relative(&path) {
                    return Err(FwError::UnsafePath(path));
                }
                let kind = entry.file_type().map_err(|e| io(Path::new(&path), e))?;
                if path == "reconstruction" && kind.is_dir() {
                    continue;
                }
                if path == SNAPSHOT && kind.is_file() {
                    continue;
                }
                if kind.is_dir() {
                    self.hash_batch(dir, &mut pending)?;
                    let child = dir
                        .open_dir_nofollow(name)
                        .map_err(|e| io(Path::new(&path), e))?;
                    self.walk(&child, &format!("{path}/"))?;
                } else if kind.is_file() {
                    pending.push(path);
                    if pending.len() == 32 {
                        self.hash_batch(dir, &mut pending)?;
                    }
                } else {
                    return Err(FwError::UnsafePath(format!(
                        "unsupported workspace node: {path}"
                    )));
                }
            }
            self.hash_batch(dir, &mut pending)
        }
    }
    let dir = files::open_root(root)?;
    let mut walker = Walker {
        entries: Vec::new(),
        visited: 0,
        remaining: files::WORKSPACE_BYTES,
        run,
    };
    walker.walk(&dir, "")?;
    walker.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(walker.entries)
}

pub(crate) fn write_snapshot(root: &Path) -> Result<Inventory> {
    write_snapshot_with_budget(root, None)
}

pub(crate) fn write_snapshot_with_budget(
    root: &Path,
    run: Option<&RunBudget>,
) -> Result<Inventory> {
    let snapshot = Snapshot {
        schema_version: 1,
        algorithm: "sha256".into(),
        excludes: vec![SNAPSHOT.into(), "reconstruction/".into()],
        files: inventory(root, run)?,
    };
    let bytes = json(&snapshot)?;
    if bytes.len() as u64 > files::MANIFEST_BYTES {
        return Err(FwError::Limit(
            "workspace integrity inventory too large".into(),
        ));
    }
    write_new(root, SNAPSHOT, &bytes)?;
    Ok(Inventory(snapshot.files))
}

pub(crate) fn verify_snapshot(root: &Path) -> Result<Inventory> {
    let recorded: Snapshot = serde_json::from_slice(&files::read_relative(
        root,
        SNAPSHOT,
        files::MANIFEST_BYTES,
    )?)?;
    if recorded.schema_version != 1
        || recorded.algorithm != "sha256"
        || recorded.excludes != [SNAPSHOT, "reconstruction/"]
        || recorded.files.len() > files::WORKSPACE_ENTRIES
    {
        return Err(FwError::Verification(
            "unsupported workspace integrity index".into(),
        ));
    }
    let current = inventory(root, None)?;
    if current != recorded.files {
        let first = current
            .iter()
            .zip(&recorded.files)
            .find(|(a, b)| *a != *b)
            .map(|(a, b)| format!("{} vs {}", a.path, b.path))
            .unwrap_or_else(|| "file count changed".into());
        return Err(FwError::Verification(format!(
            "workspace integrity mismatch: {first}"
        )));
    }
    Ok(Inventory(current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn detects_changed_and_untracked_files_but_allows_editable_source() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::create_dir_all(root.join("analysis")).unwrap();
        fs::create_dir_all(root.join("reconstruction")).unwrap();
        fs::create_dir_all(root.join("manifests")).unwrap();
        fs::write(root.join("analysis/data.json"), b"{}").unwrap();
        write_snapshot(root).unwrap();
        fs::write(root.join("reconstruction/new.rs"), b"working tree").unwrap();
        verify_snapshot(root).unwrap();
        fs::write(root.join("analysis/extra.json"), b"{}").unwrap();
        assert!(verify_snapshot(root).is_err());
        fs::remove_file(root.join("analysis/extra.json")).unwrap();
        fs::write(root.join("analysis/data.json"), b"tampered").unwrap();
        assert!(verify_snapshot(root).is_err());
    }
}
