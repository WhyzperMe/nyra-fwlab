//! The one traversal of an extracted root filesystem.
use crate::files;
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use nyra_fw_core::{FwError, Result, budget::RunBudget, errors::io, path::is_safe_relative};
use std::path::Path;

/// Where the sandbox extraction is published inside a workspace.
pub(crate) const ROOTFS_DIR: &str = "recovered/filesystems/rootfs";

/// Per-publication admission list and fingerprints. Never persisted or reused
/// across runs. Reads still use no-follow handles; publication independently
/// reconciles the final on-disk snapshot with the recorded analysis checksums.
pub(crate) struct Inventory {
    paths: Option<Vec<String>>,
    fingerprints: std::collections::BTreeMap<String, (u64, String)>,
}

impl Inventory {
    pub(crate) fn discover(root: &Path, run: &RunBudget) -> Result<Self> {
        Ok(Self {
            paths: regular_files(root, run)?,
            fingerprints: Default::default(),
        })
    }

    pub(crate) fn paths(&self) -> Option<&[String]> {
        self.paths.as_deref()
    }

    pub(crate) fn record(&mut self, path: &str, size: u64, sha256: String) -> Result<()> {
        if self
            .paths
            .as_ref()
            .is_none_or(|paths| paths.binary_search_by(|p| p.as_str().cmp(path)).is_err())
        {
            return Err(FwError::Verification(
                "file is outside admitted rootfs inventory".into(),
            ));
        }
        let value = (size, sha256);
        if let Some(previous) = self.fingerprints.get(path) {
            if previous != &value {
                return Err(FwError::Verification(
                    "rootfs changed between analysis passes".into(),
                ));
            }
        } else {
            self.fingerprints.insert(path.into(), value);
        }
        Ok(())
    }

    pub(crate) fn digest(
        &mut self,
        root: &Path,
        path: &str,
        run: &RunBudget,
    ) -> Result<(u64, String)> {
        run.checkpoint()?;
        if self
            .paths
            .as_ref()
            .is_none_or(|paths| paths.binary_search_by(|p| p.as_str().cmp(path)).is_err())
        {
            return Err(FwError::Verification(
                "file is outside admitted rootfs inventory".into(),
            ));
        }
        if let Some(value) = self.fingerprints.get(path) {
            return Ok(value.clone());
        }
        let (size, sha256) = files::digest_relative(root, path, run.limits.max_entry_bytes)?;
        self.record(path, size, sha256.clone())?;
        Ok((size, sha256))
    }
}

/// Workspace-relative paths of every regular file under the extracted rootfs.
///
/// None means the extraction directory is absent. Every component is opened
/// without following links. Enumeration is bounded before collecting entries.
pub(crate) fn regular_files(root: &Path, run: &RunBudget) -> Result<Option<Vec<String>>> {
    run.checkpoint()?;
    let mut directory = files::open_root(root)?;
    for name in ROOTFS_DIR.split('/') {
        directory = match directory.open_dir_nofollow(name) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(root.join(ROOTFS_DIR), error)),
        };
    }
    let mut found = Vec::new();
    walk(&directory, ROOTFS_DIR, run, &mut 0, &mut found)?;
    found.sort();
    Ok(Some(found))
}

fn walk(
    directory: &Dir,
    prefix: &str,
    run: &RunBudget,
    visited: &mut usize,
    found: &mut Vec<String>,
) -> Result<()> {
    let mut children = Vec::new();
    for entry in directory
        .entries()
        .map_err(|error| io(Path::new(prefix), error))?
    {
        run.checkpoint()?;
        *visited += 1;
        if *visited > run.limits.max_entries.min(files::WORKSPACE_ENTRIES) {
            return Err(FwError::Limit("rootfs walk exceeded entry limit".into()));
        }
        let entry = entry.map_err(|error| io(Path::new(prefix), error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| FwError::UnsafePath("non-UTF8 rootfs path".into()))?;
        let relative = format!("{prefix}/{name}");
        if name.contains('/') || !is_safe_relative(&relative) {
            return Err(FwError::UnsafePath(relative));
        }
        let kind = entry
            .file_type()
            .map_err(|error| io(Path::new(&relative), error))?;
        children.push((name, relative, kind));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, relative, kind) in children {
        run.checkpoint()?;
        if kind.is_dir() {
            let child = directory
                .open_dir_nofollow(&name)
                .map_err(|error| io(Path::new(&relative), error))?;
            walk(&child, &relative, run, visited, found)?;
        } else if kind.is_file() {
            found.push(relative);
        } else {
            return Err(FwError::UnsafePath(format!(
                "unsupported rootfs node: {relative}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyra_fw_core::Limits;
    use std::fs;

    #[test]
    fn fingerprints_are_local_admitted_and_detect_changed_observations() {
        let temp = tempfile::tempdir().unwrap();
        let run = RunBudget::new(Limits::default(), None);
        fs::create_dir_all(temp.path().join(ROOTFS_DIR)).unwrap();
        let relative = format!("{ROOTFS_DIR}/a");
        fs::write(temp.path().join(&relative), b"first").unwrap();
        let mut inventory = Inventory::discover(temp.path(), &run).unwrap();
        let first = inventory.digest(temp.path(), &relative, &run).unwrap();
        assert_eq!(first, (5, nyra_fw_core::sha256_hex(b"first")));
        assert_eq!(
            inventory.digest(temp.path(), &relative, &run).unwrap(),
            first
        );
        assert!(inventory.digest(temp.path(), "outside", &run).is_err());
        assert!(
            inventory
                .record(&relative, 5, nyra_fw_core::sha256_hex(b"other"))
                .is_err()
        );
        fs::write(temp.path().join(&relative), b"other").unwrap();
        let mut next_run = Inventory::discover(temp.path(), &run).unwrap();
        assert_ne!(
            next_run.digest(temp.path(), &relative, &run).unwrap(),
            first
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_replaced_extraction_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join("recovered/filesystems")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("host-data"), b"must not be read").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(ROOTFS_DIR)).unwrap();
        assert!(regular_files(&root, &RunBudget::new(Limits::default(), None)).is_err());
    }

    #[test]
    fn distinguishes_missing_and_empty_extractions_and_bounds_the_walk() {
        let temp = tempfile::tempdir().unwrap();
        let run = RunBudget::new(Limits::default(), None);
        assert!(regular_files(temp.path(), &run).unwrap().is_none());
        let rootfs = temp.path().join(ROOTFS_DIR);
        fs::create_dir_all(&rootfs).unwrap();
        assert_eq!(regular_files(temp.path(), &run).unwrap(), Some(Vec::new()));
        fs::write(rootfs.join("a"), []).unwrap();
        fs::write(rootfs.join("b"), []).unwrap();
        let run = RunBudget::new(
            Limits {
                max_entries: 1,
                ..Limits::default()
            },
            None,
        );
        assert!(matches!(
            regular_files(temp.path(), &run),
            Err(FwError::Limit(_))
        ));
        let expired = RunBudget::new(Limits::default(), Some(std::time::Instant::now()));
        assert!(matches!(
            regular_files(temp.path(), &expired),
            Err(FwError::Limit(_))
        ));
    }
}
