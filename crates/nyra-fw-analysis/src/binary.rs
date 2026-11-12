//! Deterministic ELF inspection. This does NOT execute code or claim decompilation.
use goblin::elf::{
    Elf,
    program_header::{PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD},
    sym,
};
use nyra_fw_core::{FwError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
}

/// Static PT_GNU_* observations, never a full exploitability or OS-level audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElfSecurity {
    /// None means no PT_GNU_STACK note was found, not that NX is disabled.
    pub executable_stack: Option<bool>,
    /// Segment presence alone does not prove full RELRO or BIND_NOW.
    pub has_relro_segment: bool,
    /// RWX PT_LOAD program headers are a structural warning, not a vulnerability proof.
    pub writable_executable_load_segments: usize,
    pub position_independent_elf_type: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringHit {
    /// Offset in the original ELF file, verified by scanning its actual bytes.
    pub file_offset: u64,
    /// Virtual address only when a PT_LOAD mapping covers the file offset.
    pub virtual_address: Option<u64>,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReport {
    pub source: String,
    pub sha256: String,
    pub file_type: String,
    pub machine: u16,
    pub word_size: u8,
    pub little_endian: bool,
    pub entry_point: u64,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub libraries: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub symbols: Vec<SymbolInfo>,
    pub strings: Vec<String>,
    pub string_hits: Vec<StringHit>,
    pub truncated: bool,
    pub security: ElfSecurity,
}

const MAX_SYMBOLS: usize = 20_000;
const MAX_STRINGS: usize = 2_000;
const MAX_SCANNED_BYTES: usize = 64 * 1024 * 1024;

/// File-offset indexed evidence; we deliberately avoid full-file entropy guesses.
/// The first 64 MiB and at most 2,000 matching strings are inspected.
pub fn selected_string_hits(bytes: &[u8]) -> Vec<StringHit> {
    let mut found = Vec::new();
    let mut p = 0;
    let input = &bytes[..bytes.len().min(MAX_SCANNED_BYTES)];
    while p < input.len() && found.len() < MAX_STRINGS {
        if !(32..127).contains(&input[p]) {
            p += 1;
            continue;
        }
        let start = p;
        while p < input.len() && (32..127).contains(&input[p]) {
            p += 1;
        }
        if (5..=512).contains(&(p - start)) {
            let s = String::from_utf8_lossy(&input[start..p]);
            let lower = s.to_ascii_lowercase();
            if [
                "/dev/i2c",
                "af_i2c",
                "autofocus",
                "zoom",
                "focus",
                "motor",
                "lens",
                "imx415",
                "sensor",
                "gpio",
                "ssc338",
                "calibrat",
            ]
            .iter()
            .any(|x| lower.contains(x))
            {
                found.push(StringHit {
                    file_offset: start as u64,
                    virtual_address: None,
                    text: s.into_owned(),
                });
            }
        }
    }
    found
}

fn virtual_address_for_offset(elf: &Elf<'_>, offset: u64) -> Option<u64> {
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let end = ph.p_offset.checked_add(ph.p_filesz)?;
        if (ph.p_offset..end).contains(&offset) {
            return ph.p_vaddr.checked_add(offset - ph.p_offset);
        }
    }
    None
}

pub fn inspect(source: &str, bytes: &[u8]) -> Result<BinaryReport> {
    if !bytes.starts_with(b"\x7fELF") {
        return Err(FwError::Unsupported("not an ELF file".into()));
    }
    nyra_fw_core::Limits::default().check_entry(bytes.len() as u64, bytes.len() as u64)?;
    crate::elf_limits::validate(bytes)?;
    let elf =
        Elf::parse(bytes).map_err(|e| FwError::Invalid(format!("ELF parse {source}: {e}")))?;
    Ok(from_elf(source, bytes, &elf))
}

fn from_elf(source: &str, bytes: &[u8], elf: &Elf<'_>) -> BinaryReport {
    let mut symbols = Vec::new();
    let mut truncated = false;
    for (table, strings) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        if table.len() > 100_000 {
            truncated = true;
        }
        for s in table.iter().take(100_000) {
            let Some(name) = strings.get_at(s.st_name) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if name.len() > 240 {
                truncated = true;
                continue;
            }
            if symbols.len() >= MAX_SYMBOLS {
                truncated = true;
                break;
            }
            symbols.push(SymbolInfo {
                name: name.to_owned(),
                address: s.st_value,
                size: s.st_size,
                kind: match s.st_type() {
                    sym::STT_FUNC => "function",
                    sym::STT_OBJECT => "object",
                    sym::STT_SECTION => "section",
                    _ => "other",
                }
                .into(),
            });
        }
    }
    symbols.sort_by(|a, b| a.address.cmp(&b.address).then(a.name.cmp(&b.name)));
    symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
    let mut string_hits = selected_string_hits(bytes);
    for hit in &mut string_hits {
        hit.virtual_address = virtual_address_for_offset(elf, hit.file_offset);
    }
    let mut strings: Vec<String> = string_hits.iter().map(|h| h.text.clone()).collect();
    strings.sort();
    strings.dedup();
    let mut bounded_strings = |input: &[&str]| {
        let mut values: Vec<_> = input
            .iter()
            .take(512)
            .filter_map(|value| {
                if value.len() <= 512 {
                    Some((*value).to_owned())
                } else {
                    truncated = true;
                    None
                }
            })
            .collect();
        truncated |= input.len() > 512;
        values.sort();
        values.dedup();
        values
    };
    let libraries = bounded_strings(&elf.libraries);
    let rpaths = bounded_strings(&elf.rpaths);
    let runpaths = bounded_strings(&elf.runpaths);
    let mut bounded_string = |value: Option<&str>| {
        value.and_then(|value| {
            if value.len() <= 512 {
                Some(value.to_owned())
            } else {
                truncated = true;
                None
            }
        })
    };
    let interpreter = bounded_string(elf.interpreter);
    let soname = bounded_string(elf.soname);
    BinaryReport {
        source: source.to_owned(),
        sha256: nyra_fw_core::sha256_hex(bytes),
        file_type: if elf.is_lib {
            "shared_object"
        } else {
            "executable_or_other"
        }
        .into(),
        machine: elf.header.e_machine,
        word_size: if elf.is_64 { 64 } else { 32 },
        little_endian: elf.little_endian,
        entry_point: elf.entry,
        interpreter,
        soname,
        libraries,
        rpaths,
        runpaths,
        symbols,
        strings,
        string_hits,
        truncated: truncated || bytes.len() > MAX_SCANNED_BYTES,
        security: ElfSecurity {
            executable_stack: elf
                .program_headers
                .iter()
                .find(|ph| ph.p_type == PT_GNU_STACK)
                .map(|ph| ph.p_flags & PF_X != 0),
            has_relro_segment: elf
                .program_headers
                .iter()
                .any(|ph| ph.p_type == PT_GNU_RELRO),
            writable_executable_load_segments: elf
                .program_headers
                .iter()
                .filter(|ph| ph.p_type == PT_LOAD && ph.p_flags & (PF_W | PF_X) == (PF_W | PF_X))
                .count(),
            position_independent_elf_type: elf.header.e_type == goblin::elf::header::ET_DYN,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_false_elf() {
        assert!(inspect("fake", b"\x7fELF").is_err());
    }
    #[test]
    fn reject_non_elf() {
        assert!(inspect("bad", b"PIHC").is_err());
    }
    #[test]
    fn interesting_strings_are_bounded() {
        let v = selected_string_hits(b"random words\0/dev/i2c-2\0HI_AF_I2cRunFocus\0hello");
        assert!(v.iter().any(|s| s.text == "/dev/i2c-2"));
        assert!(!v.iter().any(|s| s.text == "hello"));
        let hits = selected_string_hits(b"abc\0/dev/i2c-2\0hello");
        assert_eq!(hits[0].file_offset, 4);
        assert_eq!(hits[0].virtual_address, None);
    }
}
