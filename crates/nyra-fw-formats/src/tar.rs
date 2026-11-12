//! Read-only index of regular members in the first bounded USTAR archive.
use crate::archive::PortablePaths;
use nyra_fw_core::{FwError, Result, budget::RunBudget, path};

const BLOCK: usize = 512;
const POSIX_MAGIC: &[u8] = b"ustar\x0000";
const GNU_MAGIC: &[u8] = b"ustar  \x00";

pub struct Member<'a> {
    pub name: String,
    pub offset: usize,
    pub bytes: &'a [u8],
}

impl Member<'_> {
    pub(crate) fn header_offset(&self) -> usize {
        self.offset - BLOCK
    }
}

pub struct Archive<'a> {
    pub members: Vec<Member<'a>>,
    pub end: usize,
}

pub(crate) fn has_magic(bytes: &[u8]) -> bool {
    bytes
        .get(257..265)
        .is_some_and(|magic| magic == POSIX_MAGIC || magic == GNU_MAGIC)
}

/// Admit only regular files and directories with checksummed headers, portable
/// paths, bounded octal lengths and an explicit two-block end marker.
pub fn index<'a>(raw: &'a [u8], run: &RunBudget) -> Result<Archive<'a>> {
    let limits = &run.limits;
    limits.check_input(raw.len() as u64)?;
    let invalid =
        || FwError::Invalid("TAR header, checksum, length or end marker is invalid".into());
    let mut members = Vec::new();
    let mut names = PortablePaths::default();
    let mut start = 0;
    let mut total = 0u64;
    let mut entries = 0;
    loop {
        run.checkpoint()?;
        let data = start + BLOCK;
        let header = raw.get(start..data).ok_or_else(invalid)?;
        if header == [0; BLOCK] {
            let end = data + BLOCK;
            if entries == 0 || raw.get(data..end) != Some(&[0; BLOCK]) {
                return Err(invalid());
            }
            return Ok(Archive { members, end });
        }
        if entries >= limits.max_entries {
            return Err(FwError::Limit("too many TAR entries".into()));
        }
        entries += 1;
        let expected = octal(&header[148..156]).ok_or_else(invalid)?;
        let actual = header[..148]
            .iter()
            .chain(&header[156..])
            .map(|&b| u64::from(b))
            .sum::<u64>()
            + 8 * 32;
        if !has_magic(header) || expected != actual {
            return Err(invalid());
        }
        let size = octal(&header[124..136]).ok_or_else(invalid)?;
        let directory = match header[156] {
            b'0' | 0 => false,
            b'5' if size == 0 => true,
            _ => {
                return Err(FwError::Unsupported(
                    "TAR requires regular files and directories".into(),
                ));
            }
        };
        let name = text_field(&header[..100]).ok_or_else(invalid)?;
        let prefix = if header[257..265] == *POSIX_MAGIC {
            text_field(&header[345..500]).ok_or_else(invalid)?
        } else {
            // The GNU layout uses this area for extended attributes, not a prefix.
            ""
        };
        let name = if directory {
            name.strip_suffix('/').unwrap_or(name)
        } else {
            name
        };
        let name = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if name.len() > limits.max_path_bytes
            || !path::is_safe_relative(&name)
            || name.split('/').count() > path::MAX_DEPTH - 3
        {
            return Err(FwError::Invalid("unsafe TAR member path".into()));
        }
        // A repeated or aliasing name is a legal TAR. It cannot be copied to separate
        // portable paths, so the archive is unsupported rather than damaged.
        if !names.reserve(&name, directory, limits.max_entries)? {
            return Err(FwError::Unsupported(
                "TAR member paths repeat or alias on a portable file system".into(),
            ));
        }
        limits.check_entry(size, size)?;
        total = total.checked_add(size).ok_or_else(invalid)?;
        limits.check_total(total)?;
        let size = usize::try_from(size).map_err(|_| invalid())?;
        let end = data.checked_add(size).ok_or_else(invalid)?;
        let payload = raw.get(data..end).ok_or_else(invalid)?;
        let next = end
            .checked_add((BLOCK - size % BLOCK) % BLOCK)
            .ok_or_else(invalid)?;
        if raw
            .get(end..next)
            .is_none_or(|pad| pad.iter().any(|&b| b != 0))
        {
            return Err(invalid());
        }
        if !directory {
            members.push(Member {
                name,
                offset: data,
                bytes: payload,
            });
        }
        start = next;
    }
}

fn text_field(bytes: &[u8]) -> Option<&str> {
    let end = memchr::memchr(0, bytes).unwrap_or(bytes.len());
    bytes[end..].iter().all(|&b| b == 0).then_some(())?;
    std::str::from_utf8(&bytes[..end]).ok()
}

fn octal(mut bytes: &[u8]) -> Option<u64> {
    while bytes.first() == Some(&b' ') {
        bytes = &bytes[1..];
    }
    let digits = bytes
        .iter()
        .position(|&b| matches!(b, 0 | b' '))
        .unwrap_or(bytes.len());
    if digits == 0 || !bytes[digits..].iter().all(|&b| matches!(b, 0 | b' ')) {
        return None;
    }
    bytes[..digits].iter().try_fold(0u64, |value, &digit| {
        let digit = digit.checked_sub(b'0').filter(|&digit| digit < 8)?;
        value.checked_mul(8)?.checked_add(u64::from(digit))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, payload: &[u8], kind: u8) -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        bytes[124..135].copy_from_slice(format!("{:011o}", payload.len()).as_bytes());
        bytes[148..156].fill(b' ');
        bytes[156] = kind;
        bytes[257..265].copy_from_slice(POSIX_MAGIC);
        let sum: u64 = bytes.iter().map(|&b| u64::from(b)).sum();
        bytes[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        bytes[154] = 0;
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    }

    #[test]
    fn borrows_exact_member_ranges_and_keeps_trailing_data_outside_archive() {
        let mut bytes = member("sysupgrade/root", b"payload", b'0');
        bytes.resize(2048, 0);
        bytes.extend_from_slice(b"metadata");
        let run = RunBudget::new(Default::default(), None);
        let archive = index(&bytes, &run).unwrap();
        assert_eq!(archive.end, 2048);
        assert_eq!(archive.members[0].offset, 512);
        assert_eq!(archive.members[0].bytes, b"payload");
        for length in 0..2048 {
            assert!(index(&bytes[..length], &run).is_err(), "prefix {length}");
        }
        bytes[0] ^= 1;
        assert!(index(&bytes, &run).is_err());
    }

    #[test]
    fn repeated_names_are_unsupported_and_unsafe_names_are_invalid() {
        let run = RunBudget::new(Default::default(), None);
        let close = |mut bytes: Vec<u8>| {
            bytes.resize(bytes.len() + 1024, 0);
            bytes
        };
        // The CTERA update wrapper repeats `header` and `trailer`. Both are legal members.
        let repeated = close([member("header", b"a", b'0'), member("header", b"b", b'0')].concat());
        assert!(matches!(
            index(&repeated, &run),
            Err(FwError::Unsupported(_))
        ));
        let aliased =
            close([member("Dir/one", b"x", b'0'), member("dir/two", b"x", b'0')].concat());
        assert!(matches!(
            index(&aliased, &run),
            Err(FwError::Unsupported(_))
        ));
        let traversal = close(member("../unsafe", b"x", b'0'));
        assert!(matches!(index(&traversal, &run), Err(FwError::Invalid(_))));
    }

    #[test]
    fn rejects_paths_links_aliases_and_expansion_budget_violations() {
        let run = RunBudget::new(Default::default(), None);
        for mut bytes in [
            member("../unsafe", b"x", b'0'),
            member("NUL", b"x", b'0'),
            member("symlink", b"", b'2'),
            [member("Dir/one", b"x", b'0'), member("dir/two", b"x", b'0')].concat(),
        ] {
            bytes.resize(bytes.len() + 1024, 0);
            assert!(index(&bytes, &run).is_err());
        }
        let mut bytes = member("file", b"abc", b'0');
        bytes.resize(bytes.len() + 1024, 0);
        let limits = nyra_fw_core::Limits {
            max_total_output_bytes: 2,
            ..Default::default()
        };
        assert!(matches!(
            index(&bytes, &RunBudget::new(limits, None)),
            Err(FwError::Limit(_))
        ));
    }
}
