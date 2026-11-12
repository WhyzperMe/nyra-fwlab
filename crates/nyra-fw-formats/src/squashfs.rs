//! Read-only SquashFS identification; no untrusted external processes.
//!
//! Validation covers the superblock and the block chains of the inode and
//! directory tables. The chains matter: a superblock copied out of a container
//! that interleaves its own headers (UBI erase blocks, for example) can look
//! complete while the tables behind it no longer line up.
use crate::{bytes, magic};
use serde::{Deserialize, Serialize};

/// Largest stored size of one metadata block in the 4.0 format.
const METADATA_BLOCK_BYTES: u64 = 8192;
/// Upper bound on blocks walked per table. 64 Ki blocks describe 512 MiB of metadata.
const MAX_CHAIN_BLOCKS: u32 = 1 << 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquashFsMetadata {
    pub bytes_used: u64,
    pub inodes: u32,
    pub block_size: u32,
    pub major: u16,
    pub minor: u16,
}

pub fn inspect(bytes: &[u8]) -> Option<SquashFsMetadata> {
    validate(bytes).ok()
}

/// Follow the 16-bit block headers of a metadata table from `start`, reporting each block's
/// offset. The low 15 bits give the stored size; bit 15 marks an uncompressed block. The
/// walk must land exactly on `end`.
fn walk_chain(bytes: &[u8], start: u64, end: u64, mut visit: impl FnMut(u64)) -> bool {
    let mut at = start;
    for _ in 0..MAX_CHAIN_BLOCKS {
        if at >= end {
            return at == end;
        }
        let Some(header) = usize::try_from(at)
            .ok()
            .and_then(|position| bytes::le_u16(bytes, position))
        else {
            return false;
        };
        let size = u64::from(header & 0x7fff);
        if size == 0 || size > METADATA_BLOCK_BYTES {
            return false;
        }
        visit(at);
        at += 2 + size;
    }
    false
}

#[cfg(test)]
fn chain_ends_at(bytes: &[u8], start: u64, end: u64) -> bool {
    walk_chain(bytes, start, end, |_| {})
}

/// The offsets of every block in the chain, ascending, if it lands exactly on `end`.
fn chain_blocks(bytes: &[u8], start: u64, end: u64) -> Option<Vec<u64>> {
    let mut blocks = Vec::new();
    walk_chain(bytes, start, end, |block| blocks.push(block)).then_some(blocks)
}

/// Superblock offsets and counts that the fragment, export and id tables derive from.
struct TailTables {
    /// `(index offset, number of 64-bit block locations)` per table that exists.
    tables: Vec<(u64, u64)>,
    bytes_used: u64,
}

impl TailTables {
    fn read(bytes: &[u8], bytes_used: u64, inodes: u32) -> Option<Self> {
        let read64 = |at| bytes::le_u64(bytes, at);
        // Each table is a run of metadata blocks followed by an index of the blocks'
        // locations. The index holds one location per 8 KiB of entries.
        let blocks = |entries: u64, entry_bytes: u64| {
            entries
                .checked_mul(entry_bytes)
                .map(|size| size.div_ceil(METADATA_BLOCK_BYTES))
        };
        let mut tables = Vec::new();
        for (at, entries, entry_bytes) in [
            (80, u64::from(bytes::le_u32(bytes, 16)?), 16),
            (88, u64::from(inodes), 8),
            (48, u64::from(bytes::le_u16(bytes, 26)?), 4),
        ] {
            let start = read64(at)?;
            if start != u64::MAX {
                tables.push((start, blocks(entries, entry_bytes)?));
            }
        }
        tables.sort_unstable();
        Some(Self { tables, bytes_used })
    }

    /// Check that the tables follow the directory table without gaps and that every index entry
    /// names the start of a real metadata block. `blocks` holds the block offsets walked so far.
    fn line_up(&self, bytes: &[u8], mut blocks: Vec<u64>) -> bool {
        let mut cursor = None;
        for &(start, count) in &self.tables {
            if let Some(from) = cursor {
                match chain_blocks(bytes, from, start) {
                    Some(found) => blocks = found,
                    None => return false,
                }
            }
            let Some(end) = count
                .checked_mul(8)
                .and_then(|size| start.checked_add(size))
            else {
                return false;
            };
            if end > self.bytes_used {
                return false;
            }
            let mut previous = None;
            for index in 0..count {
                let location = usize::try_from(start + index * 8)
                    .ok()
                    .and_then(|at| bytes::le_u64(bytes, at));
                match location {
                    Some(location)
                        if previous.is_none_or(|last| location > last)
                            && blocks.binary_search(&location).is_ok() =>
                    {
                        previous = Some(location);
                    }
                    _ => return false,
                }
            }
            cursor = Some(end);
        }
        // Without extended attributes the last index ends the image.
        cursor == Some(self.bytes_used)
    }
}

/// Validate a SquashFS 4.0 image: superblock fields, table offsets and the metadata
/// block chains. The error names the first failed check.
pub fn validate(bytes: &[u8]) -> Result<SquashFsMetadata, &'static str> {
    if bytes.len() < 96 || !bytes.starts_with(magic::SQUASHFS) {
        return Err("squashfs_superblock_present");
    }
    let read32 = |at| bytes::le_u32(bytes, at);
    let read16 = |at| bytes::le_u16(bytes, at);
    let read64 = |at| bytes::le_u64(bytes, at);
    let field = "squashfs_superblock_present";
    let bytes_used = read64(40).ok_or(field)?;
    let major = read16(28).ok_or(field)?;
    let minor = read16(30).ok_or(field)?;
    let inodes = read32(4).ok_or(field)?;
    let block_size = read32(12).ok_or(field)?;
    let inode_table = read64(64).ok_or(field)?;
    let directory_table = read64(72).ok_or(field)?;
    let root = read64(32).ok_or(field)?;
    if major != 4 || minor != 0 {
        return Err("squashfs_version_4_0");
    }
    if bytes_used <= 96 || bytes_used > bytes.len() as u64 {
        return Err("squashfs_bytes_used_within_input");
    }
    if inodes == 0 || read16(26).ok_or(field)? == 0 {
        return Err("squashfs_inode_and_id_counts");
    }
    if !(1..=6).contains(&read16(20).ok_or(field)?)
        || !block_size.is_power_of_two()
        || !(4096..=1_048_576).contains(&block_size)
        || u32::from(read16(22).ok_or(field)?) != block_size.trailing_zeros()
    {
        return Err("squashfs_block_size_and_compression");
    }
    let valid_offset = |offset: u64| (96..bytes_used).contains(&offset);
    let tables_ok = valid_offset(inode_table)
        && valid_offset(directory_table)
        && inode_table < directory_table
        && root & 0xffff < 8192
        && inode_table
            .checked_add(root >> 16)
            .is_some_and(|start| start < directory_table)
        && read64(48).is_some_and(valid_offset)
        && [56, 80, 88]
            .into_iter()
            .all(|at| read64(at).is_some_and(|offset| offset == u64::MAX || valid_offset(offset)))
        && (read32(16).ok_or(field)? == 0 || read64(80).is_some_and(valid_offset));
    if !tables_ok {
        return Err("squashfs_table_offsets");
    }
    // The directory table ends where the next table begins. The tables follow it in
    // a fixed order, so the nearest later offset is its end.
    let directory_end = [48, 56, 80, 88]
        .into_iter()
        .filter_map(read64)
        .filter(|&offset| offset != u64::MAX && offset > directory_table)
        .min();
    let mut root_block_valid = false;
    let inode_chain_valid = walk_chain(bytes, inode_table, directory_table, |block| {
        if Some(block) == inode_table.checked_add(root >> 16) {
            root_block_valid = usize::try_from(block)
                .ok()
                .and_then(|at| bytes::le_u16(bytes, at))
                .is_some_and(|header| {
                    header & 0x8000 == 0 || root & 0xffff < u64::from(header & 0x7fff)
                });
        }
    });
    let directory_blocks = directory_end
        .and_then(|end| chain_blocks(bytes, directory_table, end))
        .filter(|_| inode_chain_valid && root_block_valid);
    let Some(directory_blocks) = directory_blocks else {
        return Err("squashfs_metadata_table_chains");
    };
    // An image with an extended attribute table lays out its tail differently. The tail
    // tables are checked only for the common layout without one.
    if read64(56) == Some(u64::MAX)
        && !TailTables::read(bytes, bytes_used, inodes)
            .is_some_and(|tail| tail.line_up(bytes, directory_blocks))
    {
        return Err("squashfs_metadata_table_chains");
    }
    Ok(SquashFsMetadata {
        bytes_used,
        inodes,
        block_size,
        major,
        minor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Written by `mksquashfs` 4.6.1 with gzip and one 13-byte file. `unsquashfs` lists it.
    const TINY: &[u8] = include_bytes!("../../../tests/fixtures/synthetic/tiny.squashfs");

    #[test]
    fn accepts_an_image_written_by_mksquashfs() {
        let meta = validate(TINY).unwrap();
        assert_eq!(meta.bytes_used, TINY.len() as u64);
        assert_eq!((meta.major, meta.minor), (4, 0));
    }

    #[test]
    fn rejects_tables_that_no_longer_line_up() {
        // Inserting four bytes after the superblock shifts every table the way an
        // interleaved container header would, while the superblock stays plausible.
        let mut shifted = TINY[..100].to_vec();
        shifted.extend_from_slice(&[0xa5; 4]);
        shifted.extend_from_slice(&TINY[100..]);
        let used = u64::try_from(shifted.len()).unwrap();
        shifted[40..48].copy_from_slice(&used.to_le_bytes());
        assert_eq!(
            validate(&shifted).unwrap_err(),
            "squashfs_metadata_table_chains"
        );
    }

    #[test]
    fn root_inode_must_reference_a_metadata_block_start() {
        let root = u64::from_le_bytes(TINY[32..40].try_into().unwrap());
        let mut damaged = TINY.to_vec();
        // The offset still lies inside the inode table, but points one byte into
        // the stored block rather than to its metadata header.
        damaged[32..40].copy_from_slice(&(root + (1 << 16)).to_le_bytes());
        assert_eq!(
            validate(&damaged).unwrap_err(),
            "squashfs_metadata_table_chains"
        );
    }

    fn offset_of(image: &[u8], at: usize) -> usize {
        usize::try_from(u64::from_le_bytes(image[at..at + 8].try_into().unwrap())).unwrap()
    }

    #[test]
    fn rejects_damaged_fragment_export_and_id_tables() {
        // tiny.squashfs: fragment index at 189, export blocks then index at 213, id blocks
        // then index at 227. Every table is a run of metadata blocks and an index that names them.
        let (fragment, export, id) = (
            offset_of(TINY, 80),
            offset_of(TINY, 88),
            offset_of(TINY, 48),
        );
        assert!(fragment < export && export < id && id + 8 == TINY.len());
        let rejected =
            |image: &[u8]| validate(image).unwrap_err() == "squashfs_metadata_table_chains";
        // An index entry that no longer names the start of a metadata block.
        for index in [fragment, id] {
            let mut damaged = TINY.to_vec();
            damaged[index] ^= 1;
            assert!(rejected(&damaged), "index at {index}");
        }
        // A block header inside the export table that overruns its table.
        let mut damaged = TINY.to_vec();
        let first_block = fragment + 8;
        damaged[first_block..first_block + 2].copy_from_slice(&200u16.to_le_bytes());
        assert!(rejected(&damaged));
        // Bytes counted as used behind the last index.
        let mut damaged = TINY.to_vec();
        damaged.extend_from_slice(&[0; 8]);
        let used = u64::try_from(damaged.len()).unwrap();
        damaged[40..48].copy_from_slice(&used.to_le_bytes());
        assert!(rejected(&damaged));
    }

    #[test]
    fn rejects_empty_oversized_and_overrunning_blocks() {
        for (name, header) in [
            ("empty", 0u16),
            ("oversized", 0x8000 | 8193),
            ("overrun", 0x8000 | 100),
        ] {
            let mut damaged = TINY.to_vec();
            let inode =
                usize::try_from(u64::from_le_bytes(damaged[64..72].try_into().unwrap())).unwrap();
            damaged[inode..inode + 2].copy_from_slice(&header.to_le_bytes());
            assert_eq!(
                validate(&damaged).unwrap_err(),
                "squashfs_metadata_table_chains",
                "{name}"
            );
        }
    }

    #[test]
    fn chain_walk_is_bounded_and_bounds_checked() {
        // A run of size-one blocks cannot make the walk exceed its block budget.
        let hostile: Vec<u8> = std::iter::repeat_n([1u8, 0, 0], 70_000).flatten().collect();
        assert!(!chain_ends_at(&hostile, 0, hostile.len() as u64));
        assert!(!chain_ends_at(&[], 0, 4));
        assert!(!chain_ends_at(&[3], 0, 3));
        assert!(chain_ends_at(&[], 0, 0));
    }
}
