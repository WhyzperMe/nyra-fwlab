//! Non-mutating ZIP central-directory audit for both standard and HiChip signatures.
//! Only a fully cross-checked directory is considered structurally verified.
use crate::{bytes, magic, zip::LocalEntry};
use nyra_fw_core::Limits;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryState {
    Absent,
    Valid,
    Partial,
    Malformed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAudit {
    pub state: DirectoryState,
    pub central_entries: usize,
    pub matched_local_entries: usize,
    pub mismatches: Vec<String>,
    pub note: String,
}

fn end_record(archive: &[u8], pihc: bool) -> Option<usize> {
    end_record_with(archive, pihc, !pihc)
}

/// Locate the end record whose comment length reaches the end of `archive`. For a classic
/// archive the record must also describe an archive that spans all of `archive`, unless
/// `bounded` is false. The unbounded form lets ZIP64 sentinel values be recognized.
fn end_record_with(archive: &[u8], pihc: bool, bounded: bool) -> Option<usize> {
    let last = archive.len().checked_sub(22)?;
    let start = last.saturating_sub(u16::MAX as usize);
    (start..=last).rev().find(|&at| {
        (archive[at..].starts_with(magic::ZIP_END)
            || (pihc && archive[at..].starts_with(magic::ZIP_END_HICHIP)))
            && bytes::le_u16(archive, at + 20).map(usize::from) == Some(last - at)
            && (!bounded || zip_end_bounds(archive, at) == Some((0, archive.len())))
    })
}

/// For a classic EOCD, infer the archive's start and end in its containing bytes.
pub(crate) fn zip_end_bounds(bytes: &[u8], end: usize) -> Option<(usize, usize)> {
    let size = usize::try_from(bytes::le_u32(bytes, end.checked_add(12)?)?).ok()?;
    let offset = usize::try_from(bytes::le_u32(bytes, end.checked_add(16)?)?).ok()?;
    let comment = usize::from(bytes::le_u16(bytes, end.checked_add(20)?)?);
    let start = end.checked_sub(size.checked_add(offset)?)?;
    let stop = end.checked_add(22)?.checked_add(comment)?;
    if stop > bytes.len()
        || (offset != 0 && !bytes.get(start..)?.starts_with(magic::ZIP_LOCAL))
        || (size != 0 && !bytes.get(end - size..)?.starts_with(magic::ZIP_CENTRAL))
    {
        return None;
    }
    Some((start, stop))
}

#[derive(Clone, Copy)]
pub(crate) struct LocalLayout<'a> {
    pub(crate) offset: usize,
    pub(crate) end: usize,
    pub(crate) crc: u32,
    pub(crate) compressed: u32,
    pub(crate) plain: u32,
    pub(crate) name: &'a [u8],
    pub(crate) flags: u16,
    pub(crate) method: u16,
    /// The central record marks a symbolic link, device or other special node.
    pub(crate) special_node: bool,
}

/// Why a classic 32-bit ZIP layout could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayoutError {
    /// A size, offset or count holds the ZIP64 marker value.
    Zip64,
    /// The records are absent, inconsistent or outside the single-disk classic form.
    Invalid,
}

/// Whether an end record holds the value that announces a ZIP64 count, size or offset.
fn zip64_marker(archive: &[u8], end: usize) -> bool {
    bytes::le_u16(archive, end + 10) == Some(u16::MAX)
        || bytes::le_u32(archive, end + 12) == Some(u32::MAX)
        || bytes::le_u32(archive, end + 16) == Some(u32::MAX)
}

/// Establish physical record boundaries from the central directory before
/// trusting any local length, including records written with bit 3 set.
pub(crate) fn standalone_layout<'a>(
    archive: &'a [u8],
    limits: &Limits,
) -> Result<(&'a [u8], Vec<LocalLayout<'a>>), LayoutError> {
    use LayoutError::{Invalid, Zip64};
    // The bounded search skips a forged record that merely sits at the end of a comment.
    // The unbounded one only classifies a record that holds ZIP64 marker values.
    let Some(end) = end_record_with(archive, false, true) else {
        return Err(match end_record_with(archive, false, false) {
            Some(at) if zip64_marker(archive, at) => Zip64,
            _ => Invalid,
        });
    };
    if zip64_marker(archive, end) {
        return Err(Zip64);
    }
    let offset = bytes::le_u32(archive, end + 16).ok_or(Invalid)?;
    let count = usize::from(bytes::le_u16(archive, end + 10).ok_or(Invalid)?);
    if count > limits.max_entries
        || bytes::le_u16(archive, end + 8).map(usize::from) != Some(count)
        || bytes::le_u16(archive, end + 4) != Some(0)
        || bytes::le_u16(archive, end + 6) != Some(0)
    {
        return Err(Invalid);
    }
    let offset = usize::try_from(offset).map_err(|_| Invalid)?;
    let mut layouts = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        let (name, next) = entry_bounds(archive, pos, end, limits, false).ok_or(Invalid)?;
        let name = &archive[name];
        let field = |at: usize| bytes::le_u32(archive, pos + at).ok_or(Invalid);
        let (local_offset, compressed, plain) = (field(42)?, field(20)?, field(24)?);
        if [local_offset, compressed, plain].contains(&u32::MAX) {
            return Err(Zip64);
        }
        if !on_first_disk(archive, pos) {
            return Err(Invalid);
        }
        let layout = LocalLayout {
            offset: usize::try_from(local_offset).map_err(|_| Invalid)?,
            end: offset,
            crc: field(16)?,
            compressed,
            plain,
            name,
            flags: bytes::le_u16(archive, pos + 8).ok_or(Invalid)?,
            method: bytes::le_u16(archive, pos + 10).ok_or(Invalid)?,
            special_node: !regular_node(archive, pos, name),
        };
        if layout.offset >= offset {
            return Err(Invalid);
        }
        layouts.push(layout);
        pos = next;
    }
    if pos != end
        || layouts
            .iter()
            .map(|entry| entry.offset)
            .min()
            .unwrap_or(offset)
            != 0
    {
        return Err(Invalid);
    }
    layouts.sort_unstable_by_key(|entry| entry.offset);
    for index in 1..layouts.len() {
        let next = layouts[index].offset;
        if next == layouts[index - 1].offset {
            return Err(Invalid);
        }
        layouts[index - 1].end = next;
    }
    Ok((&archive[..offset], layouts))
}

fn entry_bounds(
    archive: &[u8],
    pos: usize,
    end: usize,
    limits: &Limits,
    pihc: bool,
) -> Option<(std::ops::Range<usize>, usize)> {
    let header_end = pos.checked_add(46)?;
    if header_end > end
        || !(archive[pos..].starts_with(magic::ZIP_CENTRAL)
            || (pihc && archive[pos..].starts_with(magic::ZIP_CENTRAL_HICHIP)))
    {
        return None;
    }
    let nlen = usize::from(bytes::le_u16(archive, pos + 28)?);
    let xlen = usize::from(bytes::le_u16(archive, pos + 30)?);
    let clen = usize::from(bytes::le_u16(archive, pos + 32)?);
    let name_end = header_end.checked_add(nlen)?;
    let next = name_end.checked_add(xlen)?.checked_add(clen)?;
    (next <= end && nlen <= limits.max_path_bytes && xlen <= limits.max_extra_field_bytes)
        .then_some((header_end..name_end, next))
}

/// The central record starts on the first disk.
fn on_first_disk(archive: &[u8], pos: usize) -> bool {
    bytes::le_u16(archive, pos + 34) == Some(0)
}

/// A Unix-made record describes a plain file, or a directory when the name ends in `/`.
/// Other modes are links, devices and similar nodes.
fn regular_node(archive: &[u8], pos: usize, name: &[u8]) -> bool {
    let made_by_unix = archive[pos + 5] == 3;
    let mode = (bytes::le_u32(archive, pos + 38).unwrap_or_default() >> 16) & 0o170000;
    let expected = if name.ends_with(b"/") {
        0o040000
    } else {
        0o100000
    };
    !made_by_unix || mode == 0 || mode == expected
}

fn supported_member(archive: &[u8], pos: usize, name: &[u8]) -> bool {
    on_first_disk(archive, pos) && regular_node(archive, pos, name)
}

const VALID_NOTE: &str =
    "Central metadata matched all recovered local candidates; per-file CRC still required";

pub(crate) fn verified_directory(entries: usize) -> DirectoryAudit {
    DirectoryAudit {
        state: DirectoryState::Valid,
        central_entries: entries,
        matched_local_entries: entries,
        mismatches: Vec::new(),
        note: VALID_NOTE.into(),
    }
}

pub fn not_applicable() -> DirectoryAudit {
    DirectoryAudit {
        note: "No archive directory is available for this input".into(),
        ..absent()
    }
}

fn absent() -> DirectoryAudit {
    DirectoryAudit {
        state: DirectoryState::Absent, central_entries: 0, matched_local_entries: 0,
        mismatches: Vec::new(),
        note: "No supported ZIP end-of-central-directory record; local CRCs do not establish archive completeness".into(),
    }
}

pub fn audit(archive: &[u8], locals: &[LocalEntry], limits: &Limits) -> DirectoryAudit {
    let mut result = absent();
    let Some(end) = end_record(archive, true) else {
        return result;
    };
    result.state = DirectoryState::Malformed;
    result.note = "End-of-central-directory found but its structure failed validation".into();
    let Some(entries_on_disk) = bytes::le_u16(archive, end + 8) else {
        return result;
    };
    let Some(total) = bytes::le_u16(archive, end + 10) else {
        return result;
    };
    let Some(cd_size) = bytes::le_u32(archive, end + 12) else {
        return result;
    };
    let Some(cd_offset) = bytes::le_u32(archive, end + 16) else {
        return result;
    };
    if bytes::le_u16(archive, end + 4) != Some(0)
        || bytes::le_u16(archive, end + 6) != Some(0)
        || entries_on_disk != total
        || total == u16::MAX
        || cd_size == u32::MAX
        || cd_offset == u32::MAX
    {
        result.state = DirectoryState::Unsupported;
        result.note = "Multi-disk or ZIP64 requires a different directory reader".into();
        return result;
    }
    if total as usize > limits.max_entries {
        result.state = DirectoryState::Unsupported;
        result.note = "Central entry count exceeds configured limit".into();
        return result;
    }
    let offset = cd_offset as usize;
    let Some(cd_end) = offset.checked_add(cd_size as usize) else {
        return result;
    };
    if cd_end != end {
        return result;
    }
    let mut by_offset: BTreeMap<usize, &LocalEntry> =
        locals.iter().map(|x| (x.header_offset, x)).collect();
    let mut pos = offset;
    for _ in 0..total {
        let Some((name_range, next)) = entry_bounds(archive, pos, cd_end, limits, true) else {
            result
                .mismatches
                .push(format!("Invalid central entry at archive offset 0x{pos:x}"));
            return result;
        };
        let name = &archive[name_range];
        let local_off = bytes::le_u32(archive, pos + 42).unwrap_or(u32::MAX) as usize;
        let crc = bytes::le_u32(archive, pos + 16).unwrap_or(u32::MAX);
        let compressed = bytes::le_u32(archive, pos + 20).unwrap_or(u32::MAX) as usize;
        let plain = bytes::le_u32(archive, pos + 24).unwrap_or(u32::MAX) as usize;
        if !supported_member(archive, pos, name) {
            result.mismatches.push(format!(
                "Unsupported central file type or disk at 0x{pos:x}"
            ));
        } else if let Some(local) = by_offset.remove(&local_off) {
            if local.name.as_bytes() == name
                && local.crc32 == crc
                && local.compressed_size == compressed
                && local.uncompressed_size == plain
                && local
                    .data_offset
                    .checked_add(compressed)
                    .is_some_and(|end| end <= offset)
                && bytes::le_u16(archive, pos + 8)
                    == local_off
                        .checked_add(6)
                        .and_then(|at| bytes::le_u16(archive, at))
                && bytes::le_u16(archive, pos + 10) == Some(local.method)
            {
                result.matched_local_entries += 1;
            } else {
                result.mismatches.push(format!(
                    "Central/local metadata disagreement at 0x{local_off:x}"
                ));
            }
        } else {
            result.mismatches.push(format!(
                "Central member has no eligible local entry at 0x{local_off:x}"
            ));
        }
        result.mismatches.truncate(100);
        result.central_entries += 1;
        pos = next;
    }
    if pos != cd_end {
        result
            .mismatches
            .push("Central directory length differs from parsed entries".into());
    }
    if result.mismatches.len() > 100 {
        result.mismatches.truncate(100);
    }
    result.state = if result.mismatches.is_empty() && result.matched_local_entries == locals.len() {
        DirectoryState::Valid
    } else {
        DirectoryState::Partial
    };
    result.note = match result.state {
        DirectoryState::Valid => VALID_NOTE.into(),
        _ => "Central and local entries are not fully consistent; firmware completeness not proven"
            .into(),
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_directory_is_not_declared_complete() {
        let d = audit(b"PK\x03\x04 extra bytes", &[], &Limits::default());
        assert_eq!(d.state, DirectoryState::Absent);
    }
    #[test]
    fn crosschecks_standard_zip_directory() {
        const ZIP: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/central-valid.zip");
        let (locals, _) = crate::zip::scan_local_entries(ZIP, &Limits::default()).unwrap();
        let status = audit(ZIP, &locals, &Limits::default());
        assert_eq!(status.state, DirectoryState::Valid);
        assert_eq!(status.matched_local_entries, 1);
        let mut tampered = ZIP.to_vec();
        let at = tampered
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .unwrap();
        tampered[at + 16] ^= 0x55;
        assert_eq!(
            audit(&tampered, &locals, &Limits::default()).state,
            DirectoryState::Partial
        );
    }
    #[test]
    fn bogus_directory_does_not_panic() {
        let mut bytes = vec![0; 100];
        bytes[78..82].copy_from_slice(b"PK\x05\x09");
        bytes[94..98].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            audit(&bytes, &[], &Limits::default()).state,
            DirectoryState::Malformed
        );
    }
}
