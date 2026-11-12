//! Conservative scanner for HiChip's modified ZIP local file headers.
//! It does not claim that a complete ZIP central directory was recovered.
use crate::{
    archive::{ArchiveIssue, Exclusion, PortablePaths},
    bytes,
    central::LocalLayout,
    magic,
};
use nyra_fw_core::{FwError, Limits, Result};

#[derive(Debug, Clone)]
pub struct LocalEntry {
    pub name: String,
    pub header_offset: usize,
    pub data_offset: usize,
    pub compressed_size: usize,
    pub uncompressed_size: usize,
    pub crc32: u32,
    pub method: u16,
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub signatures: usize,
    pub directories: usize,
    pub eligible: usize,
    pub unsupported: usize,
    pub duplicate_names: usize,
    pub invalid_headers: usize,
}

/// A PIHC member name must be a portable, printable-ASCII relative path. The
/// vendor directory layout is not assumed, because packages for other devices use
/// other roots. A header in noise cannot pass: the member still needs its CRC32,
/// exact size and exact stream end. Non-ASCII names are excluded rather than
/// silently mis-decoded.
pub fn safe_member_path(name: &str) -> bool {
    nyra_fw_core::path::is_safe_relative(name)
}

pub fn scan_local_entries(archive: &[u8], limits: &Limits) -> Result<(Vec<LocalEntry>, ScanStats)> {
    scan(archive, limits).map(|(entries, stats, _)| (entries, stats))
}

/// What an indexed local record must satisfy to be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Local and central records agree, and the member can be extracted: supported
    /// encoding, portable unique path, no special node.
    Extractable,
    /// Local and central records agree. Encoding, path and node type are not judged.
    Structure,
}

pub(crate) fn scan(
    archive: &[u8],
    limits: &Limits,
) -> Result<(Vec<LocalEntry>, ScanStats, Vec<ArchiveIssue>)> {
    let positions = memchr::memchr_iter(b'P', &archive[..archive.len().saturating_sub(3)])
        .map(|pos| (pos, None));
    scan_records(archive, limits, true, Admission::Extractable, positions)
}

pub(crate) fn scan_indexed(
    archive: &[u8],
    limits: &Limits,
    layout: &[LocalLayout<'_>],
    admission: Admission,
) -> Result<(Vec<LocalEntry>, ScanStats, Vec<ArchiveIssue>)> {
    scan_records(
        archive,
        limits,
        false,
        admission,
        layout.iter().map(|entry| (entry.offset, Some(entry))),
    )
}

fn scan_records<'a>(
    archive: &[u8],
    limits: &Limits,
    pihc: bool,
    admission: Admission,
    positions: impl Iterator<Item = (usize, Option<&'a LocalLayout<'a>>)>,
) -> Result<(Vec<LocalEntry>, ScanStats, Vec<ArchiveIssue>)> {
    limits.check_input(archive.len() as u64)?;
    let mut found = Vec::new();
    let mut stats = ScanStats::default();
    let mut seen = PortablePaths::default();
    let mut accepted_end = 0;
    let mut issues = Vec::new();

    for (pos, layout) in positions {
        if pos < accepted_end {
            continue;
        }
        let Some(sig) = archive.get(pos..pos + 4) else {
            continue;
        };
        if sig != magic::ZIP_LOCAL && (!pihc || sig != magic::ZIP_LOCAL_HICHIP) {
            continue;
        }
        stats.signatures += 1;
        if stats.signatures > limits.max_entries.saturating_mul(4) {
            return Err(FwError::Limit("excessive ZIP signature candidates".into()));
        }
        let mut exclude = |reason| {
            issues.push(ArchiveIssue {
                header_offset: pos as u64,
                reason,
            })
        };
        if archive.len() - pos < 30 {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        }
        let flags = u16::from_le_bytes([archive[pos + 6], archive[pos + 7]]);
        let method = u16::from_le_bytes([archive[pos + 8], archive[pos + 9]]);
        let mut crc32 = u32::from_le_bytes(
            archive[pos + 14..pos + 18]
                .try_into()
                .map_err(|_| FwError::Invalid("ZIP crc".into()))?,
        );
        let mut comp = u32::from_le_bytes(
            archive[pos + 18..pos + 22]
                .try_into()
                .map_err(|_| FwError::Invalid("ZIP compressed size".into()))?,
        ) as usize;
        let mut plain = u32::from_le_bytes(
            archive[pos + 22..pos + 26]
                .try_into()
                .map_err(|_| FwError::Invalid("ZIP uncompressed size".into()))?,
        ) as usize;
        let nlen = u16::from_le_bytes([archive[pos + 26], archive[pos + 27]]) as usize;
        let extra = u16::from_le_bytes([archive[pos + 28], archive[pos + 29]]) as usize;
        if nlen == 0 || nlen > limits.max_path_bytes || extra > limits.max_extra_field_bytes {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        }
        let Some(start) = pos
            .checked_add(30)
            .and_then(|n| n.checked_add(nlen))
            .and_then(|n| n.checked_add(extra))
        else {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        };
        let descriptor = flags & 8 != 0 && layout.is_some();
        if let Some(layout) = layout.filter(|_| descriptor) {
            if (crc32 != 0 && crc32 != layout.crc)
                || (comp != 0 && comp != layout.compressed as usize)
                || (plain != 0 && plain != layout.plain as usize)
            {
                stats.invalid_headers += 1;
                exclude(Exclusion::InvalidHeader);
                continue;
            }
            (crc32, comp, plain) = (
                layout.crc,
                layout.compressed as usize,
                layout.plain as usize,
            );
        }
        let Some(end) = start.checked_add(comp) else {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        };
        if end > archive.len() {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        }
        if let Some(layout) = layout {
            let matched = if descriptor {
                archive
                    .get(end..layout.end)
                    .is_some_and(|trailer| descriptor_matches(trailer, layout))
            } else {
                end == layout.end
            };
            if !matched {
                stats.invalid_headers += 1;
                exclude(Exclusion::InvalidHeader);
                continue;
            }
        }
        if flags & 8 == 0 {
            accepted_end = end;
        }
        let raw_name = &archive[pos + 30..pos + 30 + nlen];
        let name = match std::str::from_utf8(raw_name) {
            Ok(name) => name,
            Err(_) if admission == Admission::Structure => "",
            Err(_) => {
                stats.unsupported += 1;
                exclude(Exclusion::UnsupportedName);
                continue;
            }
        };
        if layout.is_some_and(|layout| {
            layout.name != raw_name
                || layout.flags != flags
                || layout.method != method
                || layout.crc != crc32
                || layout.compressed as usize != comp
                || layout.plain as usize != plain
        }) {
            stats.invalid_headers += 1;
            exclude(Exclusion::InvalidHeader);
            continue;
        }
        let directory = raw_name.ends_with(b"/");
        if admission == Admission::Extractable {
            let path = name.strip_suffix('/').unwrap_or(name);
            let exclusion = if !nyra_fw_core::path::is_safe_relative(path)
                || path.split('/').count() > nyra_fw_core::path::MAX_DEPTH - 2
                || (pihc && !directory && !safe_member_path(path))
            {
                Some(Exclusion::UnsupportedName)
            } else if flags & !(0x0806 | if descriptor { 8 } else { 0 }) != 0
                || !matches!(method, 0 | 8)
                || (method == 0 && (comp != plain || flags & 6 != 0))
                || (directory && (plain != 0 || crc32 != 0))
                || layout.is_some_and(|layout| layout.special_node)
            {
                Some(Exclusion::UnsupportedEncoding)
            } else if limits.check_entry(comp as u64, plain as u64).is_err() {
                Some(Exclusion::EntryLimit)
            } else {
                None
            };
            if let Some(reason) = exclusion {
                stats.unsupported += 1;
                exclude(reason);
                continue;
            }
            // Reserve both file names and implicit parents. This prevents aliasing on
            // case-insensitive filesystems and file/directory prefix collisions.
            let path = name.strip_suffix('/').unwrap_or(name);
            if !seen.reserve(path, directory, limits.max_entries)? {
                stats.duplicate_names += 1;
                exclude(Exclusion::PathCollision);
                continue;
            }
        }
        if directory {
            stats.directories += 1;
        }
        if directory && pihc {
            continue;
        }
        if found.len() >= limits.max_entries {
            return Err(FwError::Limit("too many ZIP members".into()));
        }
        found.push(LocalEntry {
            name: name.to_owned(),
            header_offset: pos,
            data_offset: start,
            compressed_size: comp,
            uncompressed_size: plain,
            crc32,
            method,
        });
        if !directory {
            stats.eligible += 1;
        }
    }
    Ok((found, stats, issues))
}

fn descriptor_matches(trailer: &[u8], layout: &LocalLayout<'_>) -> bool {
    let fields = match trailer.len() {
        12 => trailer,
        16 if trailer.starts_with(magic::ZIP_DESCRIPTOR) => &trailer[4..],
        _ => return false,
    };
    bytes::le_u32(fields, 0) == Some(layout.crc)
        && bytes::le_u32(fields, 4) == Some(layout.compressed)
        && bytes::le_u32(fields, 8) == Some(layout.plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 30];
        bytes[..4].copy_from_slice(magic::ZIP_LOCAL);
        bytes[14..18].copy_from_slice(&crc32fast::hash(payload).to_le_bytes());
        bytes[18..22].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[22..26].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn excludes_overlaps_and_portable_aliases() {
        let nested = stored("config/nested", b"nested payload");
        let mut archive = stored("config/Directory/first", &nested);
        archive.extend(stored("config/directory/second", b"case collision"));
        archive.extend(stored("config/Directory", b"directory collision"));
        archive.extend(stored("config/Directory/first/child", b"file collision"));
        let (entries, stats) = scan_local_entries(&archive, &Limits::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "config/Directory/first");
        assert_eq!(stats.duplicate_names, 3);
    }
    #[test]
    fn traversal_and_windows_names_refused() {
        for name in [
            "../etc/passwd",
            "mnt/mtd/ipc/../../x",
            "mnt/mtd/ipc/NUL.txt",
            "mnt/mtd/ipc/a\\b",
            "mnt/mtd/ipc/C:x",
            "mnt/mtd/ipc/a/./b",
            "mnt/mtd/ipc/a.",
            "mnt/mtd/ipc/a\n",
        ] {
            assert!(!safe_member_path(name), "accepted {name:?}");
        }
        assert!(safe_member_path("mnt/mtd/ipc/ipc_server"));
        assert!(safe_member_path("config/settings.ini"));
        // Other device families use other roots; unsafe forms stay refused.
        assert!(safe_member_path("etc/init.d/rcS"));
        for name in ["/etc/shadow", "", "etc//x", "etc/../x", "caf\u{e9}/x"] {
            assert!(!safe_member_path(name), "accepted {name:?}");
        }
    }
}
