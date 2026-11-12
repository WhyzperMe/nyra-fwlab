//! Bounded reads through directory handles. Reject links at every workspace component.
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use nyra_fw_core::{FwError, Result, errors::io, path::is_safe_relative};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub(crate) const MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const REPORT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const WORKSPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const WORKSPACE_ENTRIES: usize = 50_000;

pub(crate) fn open_root(path: &Path) -> Result<Dir> {
    if let Some(name) = path.file_name() {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|e| io(parent, e))?;
        return dir.open_dir_nofollow(name).map_err(|e| io(path, e));
    }
    Dir::open_ambient_dir(path, ambient_authority()).map_err(|e| io(path, e))
}

pub(crate) struct RegularFile {
    handle: File,
    len: u64,
}

impl RegularFile {
    pub(crate) fn len(&self) -> u64 {
        self.len
    }
}

pub(crate) fn open_regular(dir: &Dir, name: &Path) -> Result<RegularFile> {
    let metadata = dir.symlink_metadata(name).map_err(|e| io(name, e))?;
    if !metadata.is_file() {
        return Err(FwError::UnsafePath(name.display().to_string()));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = dir.open_with(name, &options).map_err(|e| io(name, e))?;
    let metadata = file.metadata().map_err(|e| io(name, e))?;
    if !metadata.is_file() {
        return Err(FwError::UnsafePath(name.display().to_string()));
    }
    Ok(RegularFile {
        handle: file,
        len: metadata.len(),
    })
}

pub(crate) fn open_relative(root: &Path, relative: &str) -> Result<RegularFile> {
    if !is_safe_relative(relative) {
        return Err(FwError::UnsafePath(relative.into()));
    }
    let mut parts = relative.rsplitn(2, '/');
    let name = parts.next().unwrap_or_default();
    let mut dir = open_root(root)?;
    if let Some(parent) = parts.next() {
        for component in parent.split('/') {
            dir = dir
                .open_dir_nofollow(component)
                .map_err(|e| io(root.join(relative), e))?;
        }
    }
    open_regular(&dir, Path::new(name))
}

pub(crate) fn read_relative(root: &Path, relative: &str, max: u64) -> Result<Vec<u8>> {
    read_file(open_relative(root, relative)?, &root.join(relative), max)
}

/// Inspect a prefix and read an admitted candidate through the same checked handle.
pub(crate) fn read_matching(
    root: &Path,
    relative: &str,
    prefix: &[u8],
    max: u64,
) -> Result<Option<Vec<u8>>> {
    let mut file = open_relative(root, relative)?;
    let path = root.join(relative);
    if file.len > max {
        return Err(oversize(&path, max));
    }
    if file.len < prefix.len() as u64 {
        return Ok(None);
    }
    let mut header = vec![0; prefix.len()];
    file.handle
        .read_exact(&mut header)
        .map_err(|error| io(&path, error))?;
    if header != prefix {
        return Ok(None);
    }
    file.handle
        .seek(SeekFrom::Start(0))
        .map_err(|error| io(&path, error))?;
    read_file(file, &path, max).map(Some)
}

pub fn read_input(path: &Path, max: u64) -> Result<Vec<u8>> {
    let name = path
        .file_name()
        .ok_or_else(|| FwError::UnsafePath(path.display().to_string()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|e| io(parent, e))?;
    read_file(open_regular(&dir, Path::new(name))?, path, max)
}

pub(crate) fn read_file(file: RegularFile, path: &Path, max: u64) -> Result<Vec<u8>> {
    let RegularFile { handle, len: size } = file;
    if size > max {
        return Err(oversize(path, max));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(size).map_err(|_| oversize(path, max))?)
        .map_err(|_| {
            FwError::Limit(format!(
                "cannot allocate input buffer for {}",
                path.display()
            ))
        })?;
    handle
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(path, e))?;
    if bytes.len() as u64 != size {
        return Err(FwError::Verification(format!(
            "file size changed while reading {}",
            path.display()
        )));
    }
    Ok(bytes)
}

pub(crate) fn digest(input: RegularFile, path: &Path, max: u64) -> Result<(u64, String)> {
    let RegularFile { handle, len } = input;
    if len > max {
        return Err(oversize(path, max));
    }
    let mut hash = Sha256::new();
    let mut input = handle.take(len.saturating_add(1));
    let mut buffer = [0u8; 65536];
    let mut size = 0u64;
    loop {
        let read = input.read(&mut buffer).map_err(|e| io(path, e))?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > max {
            return Err(oversize(path, max));
        }
        hash.update(&buffer[..read]);
    }
    if size != len {
        return Err(FwError::Verification(format!(
            "file size changed while hashing {}",
            path.display()
        )));
    }
    Ok((size, hex::encode(hash.finalize())))
}

pub(crate) fn digest_relative(root: &Path, path: &str, max: u64) -> Result<(u64, String)> {
    digest(open_relative(root, path)?, &root.join(path), max)
}

fn oversize(path: &Path, max: u64) -> FwError {
    FwError::Limit(format!("{} exceeds {max} bytes", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn prefix_admission_checks_the_limit_and_preserves_the_entire_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("elf"), b"ELF-content").unwrap();
        assert_eq!(
            read_matching(temp.path(), "elf", b"ELF", 32).unwrap(),
            Some(b"ELF-content".to_vec())
        );
        assert!(
            read_matching(temp.path(), "elf", b"other", 32)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_matching(temp.path(), "elf", b"ELF", 3),
            Err(FwError::Limit(_))
        ));
    }

    #[test]
    fn rejects_size_changes_after_a_handle_has_been_admitted() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        fs::write(&path, b"original").unwrap();
        let admitted = open_relative(temp.path(), "source").unwrap();
        fs::write(&path, b"larger replacement").unwrap();
        assert!(matches!(
            read_file(admitted, &path, 64),
            Err(FwError::Verification(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_handle_survives_path_replacement_and_new_reads_reject_the_link() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        fs::write(&path, b"original").unwrap();
        let admitted = open_relative(temp.path(), "source").unwrap();
        fs::rename(&path, temp.path().join("retained")).unwrap();
        fs::write(temp.path().join("outside"), b"other bytes").unwrap();
        std::os::unix::fs::symlink(temp.path().join("outside"), &path).unwrap();
        assert_eq!(read_file(admitted, &path, 64).unwrap(), b"original");
        assert!(read_relative(temp.path(), "source", 64).is_err());
        assert!(read_matching(temp.path(), "source", b"other", 64).is_err());
    }
}
