//! Format-specific header checks. Each returns the name of the first failed check.
use crate::bytes;
pub(crate) fn elf_extent(bytes: &[u8]) -> std::result::Result<u64, &'static str> {
    if !bytes.starts_with(crate::magic::ELF) {
        return Err("elf_magic");
    }
    let class = *bytes.get(4).ok_or("elf_header_present")?;
    let data = *bytes.get(5).ok_or("elf_header_present")?;
    let (header, phentsize, shentsize) = match class {
        1 => (52usize, 32u64, 40u64),
        2 => (64, 56, 64),
        _ => return Err("elf_class_and_encoding"),
    };
    if !matches!(data, 1 | 2) || bytes.get(6) != Some(&1) {
        return Err("elf_class_and_encoding");
    }
    if bytes.len() < header {
        return Err("elf_header_present");
    }
    let little = data == 1;
    let u16_at = |at: usize| -> u64 {
        let raw = [bytes[at], bytes[at + 1]];
        u64::from(if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    };
    let u32_at = |at: usize| -> u64 {
        let raw = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        u64::from(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    let word = |at32: usize, at64: usize| -> u64 {
        if class == 1 {
            u32_at(at32)
        } else {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[at64..at64 + 8]);
            if little {
                u64::from_le_bytes(raw)
            } else {
                u64::from_be_bytes(raw)
            }
        }
    };
    let (phoff, shoff) = (word(28, 32), word(32, 40));
    let (e_ehsize, e_phentsize, phnum, e_shentsize, shnum) = if class == 1 {
        (u16_at(40), u16_at(42), u16_at(44), u16_at(46), u16_at(48))
    } else {
        (u16_at(52), u16_at(54), u16_at(56), u16_at(58), u16_at(60))
    };
    if !(1..=4).contains(&u16_at(16)) || u32_at(20) != 1 || e_ehsize != header as u64 {
        return Err("elf_type_version_and_header_size");
    }
    if (phnum == 0 && shnum == 0) || phnum > 4096 || shnum > 4096 {
        return Err("elf_table_counts_bounded");
    }
    let len = bytes.len() as u64;
    let mut extent = header as u64;
    if phnum != 0 {
        let end = phoff.checked_add(phnum * phentsize);
        if e_phentsize != phentsize || phoff < header as u64 || end.is_none_or(|end| end > len) {
            return Err("elf_program_headers_within_input");
        }
        extent = extent.max(end.unwrap_or(0));
        for index in 0..phnum {
            let at = (phoff + index * phentsize) as usize;
            let (offset, size) = if class == 1 {
                (u32_at(at + 4), u32_at(at + 16))
            } else {
                let read = |from: usize| {
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&bytes[at + from..at + from + 8]);
                    if little {
                        u64::from_le_bytes(raw)
                    } else {
                        u64::from_be_bytes(raw)
                    }
                };
                (read(8), read(32))
            };
            let end = offset.checked_add(size).filter(|&end| end <= len);
            extent = extent.max(end.ok_or("elf_segments_within_input")?);
        }
    }
    if shnum != 0 {
        let end = shoff.checked_add(shnum * shentsize);
        if e_shentsize != shentsize || shoff < header as u64 || end.is_none_or(|end| end > len) {
            return Err("elf_section_headers_within_input");
        }
        extent = extent.max(end.unwrap_or(0));
        for index in 0..shnum {
            let at = (shoff + index * shentsize) as usize;
            let kind = u32_at(at + 4);
            let (offset, size) = if class == 1 {
                (u32_at(at + 16), u32_at(at + 20))
            } else {
                let read = |from: usize| {
                    let mut raw = [0u8; 8];
                    raw.copy_from_slice(&bytes[at + from..at + from + 8]);
                    if little {
                        u64::from_le_bytes(raw)
                    } else {
                        u64::from_be_bytes(raw)
                    }
                };
                (read(24), read(32))
            };
            if kind == 8 || kind == 0 {
                continue;
            }
            let end = offset.checked_add(size).filter(|&end| end <= len);
            extent = extent.max(end.ok_or("elf_sections_within_input")?);
        }
    }
    Ok(extent)
}

pub(super) fn fdt_extent(
    bytes: &[u8],
    charge: impl FnOnce(u64) -> bool,
) -> std::result::Result<u64, &'static str> {
    let word = |at: usize| -> Option<u64> { bytes::be_u32(bytes, at).map(u64::from) };
    let field = |index: usize| word(index * 4).ok_or("fdt_header_present");
    let total = field(1)?;
    let (structure, strings, reserve) = (field(2)?, field(3)?, field(4)?);
    let (version, compatible) = (field(5)?, field(6)?);
    let strings_size = field(8)?;
    if !(40..=1 << 26).contains(&total) || total > bytes.len() as u64 {
        return Err("fdt_total_size_within_input");
    }
    if !(16..=17).contains(&version) || compatible == 0 || compatible > version {
        return Err("fdt_version");
    }
    let header_size = if version == 17 { 40 } else { 36 };
    let structure_size = if version == 17 {
        field(9)?
    } else {
        strings.checked_sub(structure).ok_or("fdt_block_order")?
    };
    let within = |start: u64, size: u64| start.checked_add(size).is_some_and(|end| end <= total);
    if !within(structure, structure_size)
        || !within(strings, strings_size)
        || reserve % 8 != 0
        || reserve < header_size
        || structure < header_size
        || strings < header_size
        || !within(reserve, 16)
        || structure % 4 != 0
        || structure_size < 8
        || structure_size % 4 != 0
    {
        return Err("fdt_block_bounds_and_alignment");
    }
    let struct_end = structure + structure_size;
    let strings_end = strings + strings_size;
    let overlap = |a: u64, b: u64, c: u64, d: u64| a < b && c < d && a < d && c < b;
    if overlap(structure, struct_end, strings, strings_end) {
        return Err("fdt_block_overlap");
    }
    if !charge(total) {
        return Err("fdt_validation_budget");
    }
    let mut at = reserve;
    loop {
        if !within(at, 16)
            || overlap(at, at + 16, structure, struct_end)
            || overlap(at, at + 16, strings, strings_end)
        {
            return Err("fdt_reservation_terminator");
        }
        if bytes[at as usize..at as usize + 16] == [0; 16] {
            break;
        }
        at += 16;
    }
    fdt_tokens(
        &bytes[structure as usize..struct_end as usize],
        &bytes[strings as usize..strings_end as usize],
        version == 16,
    )?;
    Ok(total)
}

fn fdt_tokens(
    mut block: &[u8],
    strings: &[u8],
    trailing_padding: bool,
) -> std::result::Result<(), &'static str> {
    let error = "fdt_structure_tokens";
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut children = [false; 128];
    loop {
        let token = bytes::be_u32(block, 0).ok_or(error)?;
        block = &block[4..];
        match token {
            1 if depth < children.len() && (depth != 0 || !root_seen) => {
                let name = memchr::memchr(0, &block[..block.len().min(1024)]).ok_or(error)?;
                if (depth == 0) != (name == 0) {
                    return Err(error);
                }
                if depth > 0 {
                    children[depth - 1] = true;
                }
                children[depth] = false;
                depth += 1;
                root_seen = true;
                block = fdt_skip(block, name + 1).ok_or(error)?;
            }
            2 if depth > 0 => depth -= 1,
            3 if depth > 0 && !children[depth - 1] => {
                let size = bytes::be_u32(block, 0).ok_or(error)? as usize;
                let name = bytes::be_u32(block, 4).ok_or(error)? as usize;
                let name = strings.get(name..).ok_or("fdt_property_name")?;
                if memchr::memchr(0, &name[..name.len().min(256)]).is_none_or(|end| end == 0) {
                    return Err("fdt_property_name");
                }
                block = fdt_skip(&block[8..], size).ok_or(error)?;
            }
            4 => {}
            9 if root_seen
                && depth == 0
                && (block.is_empty() || trailing_padding && block.iter().all(|&b| b == 0)) =>
            {
                return Ok(());
            }
            _ => return Err(error),
        }
    }
}

fn fdt_skip(bytes: &[u8], size: usize) -> Option<&[u8]> {
    let end = size.checked_add(3)? & !3;
    if bytes.get(size..end)?.iter().any(|&byte| byte != 0) {
        return None;
    }
    bytes.get(end..)
}
pub(super) fn ubi_header(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    let header = bytes.get(..64).ok_or("ubi_header_present")?;
    let be32 = |at: usize| bytes::be_u32(header, at).unwrap_or_default();
    if header[4] != 1 || header[5..8] != [0; 3] {
        return Err("ubi_version_and_padding");
    }
    let (vid, data) = (be32(16), be32(20));
    if vid < 64 || data <= vid || data > 4 * 1024 * 1024 {
        return Err("ubi_header_offsets");
    }
    // UBI stores the CRC-32 without the final inversion.
    if !crc32fast::hash(&header[..60]) != be32(60) {
        return Err("ubi_header_crc32");
    }
    Ok(())
}

pub(super) fn xz_header(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    let header = bytes.get(..12).ok_or("xz_header_present")?;
    let flags = &header[6..8];
    let crc = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if flags[0] != 0 || flags[1] > 0x0f || crc32fast::hash(flags) != crc {
        return Err("xz_stream_header_crc32");
    }
    Ok(())
}
