//! Preflight goblin's eager tables before it can allocate or walk them.
use goblin::{
    container::{Container, Ctx, Endian},
    elf::{
        Elf, dynamic, header,
        program_header::{self, ProgramHeader},
        section_header::{self, SectionHeader},
    },
};
use nyra_fw_core::{FwError, Result};

const MAX_STRING_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRINGS: usize = 262_144;

pub(crate) fn validate(bytes: &[u8]) -> Result<()> {
    let invalid = |message: &str| FwError::Invalid(format!("ELF {message}"));
    let h = Elf::parse_header(bytes).map_err(|e| invalid(&e.to_string()))?;
    let (class, ehsize, phsize, shsize) = match h.e_ident[header::EI_CLASS] {
        header::ELFCLASS32 => (Container::Little, 52, 32, 40),
        header::ELFCLASS64 => (Container::Big, 64, 56, 64),
        _ => return Err(invalid("class")),
    };
    let endian = match h.e_ident[header::EI_DATA] {
        header::ELFDATA2LSB => Endian::Little,
        header::ELFDATA2MSB => Endian::Big,
        _ => return Err(invalid("byte order")),
    };
    let ctx = Ctx::new(class, endian);
    if h.e_ehsize != ehsize || h.e_version != 1 || h.e_ident[header::EI_VERSION] != 1 {
        return Err(invalid("header size or version"));
    }
    if h.e_phnum > 256 || h.e_shnum > 4096 {
        return Err(FwError::Limit("ELF header table entry count".into()));
    }
    // Extended counts would bypass the entry limits above. Leave these inputs
    // in the workspace as parse failures with their original bytes available.
    if (h.e_phnum != 0 && (h.e_phentsize != phsize || h.e_phoff < u64::from(ehsize)))
        || (h.e_shnum != 0 && (h.e_shentsize != shsize || h.e_shoff < u64::from(ehsize)))
        || (h.e_shnum == 0 && h.e_shoff != 0)
    {
        return Err(invalid(
            "table layout or unsupported extended section count",
        ));
    }
    let phoff = usize::try_from(h.e_phoff).map_err(|_| invalid("program table offset"))?;
    let shoff = usize::try_from(h.e_shoff).map_err(|_| invalid("section table offset"))?;
    let ph = ProgramHeader::parse(bytes, phoff, usize::from(h.e_phnum), ctx)
        .map_err(|e| invalid(&e.to_string()))?;
    let sh = SectionHeader::parse(bytes, shoff, usize::from(h.e_shnum), ctx)
        .map_err(|e| invalid(&e.to_string()))?;
    for p in &ph {
        if p.p_filesz != 0 {
            range(bytes, p.p_offset, p.p_filesz)?;
        }
        if p.p_type == program_header::PT_LOAD
            && (p.p_filesz > p.p_memsz || p.p_vaddr.checked_add(p.p_memsz).is_none())
        {
            return Err(invalid("load segment range"));
        }
        if p.p_type == program_header::PT_DYNAMIC && p.p_filesz > 16 * 1024 {
            return Err(FwError::Limit("ELF dynamic segment exceeds 16 KiB".into()));
        }
    }
    let mut string_bytes = 0usize;
    for section in &sh {
        if section.sh_type != section_header::SHT_NOBITS && section.sh_size != 0 {
            let data = range(bytes, section.sh_offset, section.sh_size)?;
            if section.sh_type == section_header::SHT_STRTAB {
                string_bytes = string_bytes.saturating_add(data.len());
                if string_bytes > MAX_STRING_BYTES {
                    return Err(FwError::Limit("ELF string tables exceed 8 MiB".into()));
                }
                validate_strings(data)?;
            }
        }
    }
    let string_index = if u32::from(h.e_shstrndx) == section_header::SHN_XINDEX {
        sh.first()
            .map_or(usize::MAX, |first| first.sh_link as usize)
    } else {
        h.e_shstrndx as usize
    };
    if string_index != 0
        && sh
            .get(string_index)
            .is_none_or(|s| s.sh_type != section_header::SHT_STRTAB)
    {
        return Err(invalid("invalid section-name string table"));
    }
    if sh.iter().any(|s| {
        s.sh_type == section_header::SHT_SYMTAB
            && (s.sh_entsize != if class.is_big() { 24 } else { 16 }
                || sh
                    .get(s.sh_link as usize)
                    .is_none_or(|link| link.sh_type != section_header::SHT_STRTAB))
    }) {
        return Err(invalid("invalid symbol table layout"));
    }
    if let Some(dyns) =
        dynamic::Dynamic::parse(bytes, &ph, ctx).map_err(|e| invalid(&e.to_string()))?
    {
        let info = dyns.info;
        validate_strings(range(bytes, info.strtab as u64, info.strsz as u64)?)?;
        for size in [info.relasz, info.relsz, info.pltrelsz] {
            if size > 4 * 1024 * 1024 {
                return Err(FwError::Limit(
                    "ELF dynamic relocation table exceeds 4 MiB".into(),
                ));
            }
        }
    }
    Ok(())
}

fn range(bytes: &[u8], start: u64, size: u64) -> Result<&[u8]> {
    let slice = start
        .checked_add(size)
        .and_then(|end| Some((usize::try_from(start).ok()?, usize::try_from(end).ok()?)))
        .and_then(|(start, end)| bytes.get(start..end));
    slice.ok_or_else(|| FwError::Invalid("ELF range extends beyond input".into()))
}

fn validate_strings(data: &[u8]) -> Result<()> {
    if data.len() > MAX_STRING_BYTES
        || data
            .iter()
            .filter(|&&b| b == 0)
            .take(MAX_STRINGS + 1)
            .count()
            > MAX_STRINGS
    {
        return Err(FwError::Limit("ELF string table allocation limit".into()));
    }
    if !data.is_empty() && data.last() != Some(&0) {
        return Err(FwError::Invalid("unterminated ELF string table".into()));
    }
    Ok(())
}
