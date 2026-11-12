//! Exclusive creation of files inside the staging tree.
use nyra_fw_core::{FwError, Result, errors::io, path::is_safe_relative};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

/// Create `relative` under `root` and write `bytes`. An existing file is an error,
/// so a stage can never overwrite evidence it already wrote.
pub(crate) fn write_new(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    if !is_safe_relative(relative) {
        return Err(FwError::UnsafePath(relative.into()));
    }
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| io(&path, e))?;
    file.write_all(bytes).map_err(|e| io(&path, e))?;
    file.sync_all().map_err(|e| io(&path, e))?;
    Ok(())
}

/// Pretty JSON as written to every report.
pub(crate) fn json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(value)?)
}
