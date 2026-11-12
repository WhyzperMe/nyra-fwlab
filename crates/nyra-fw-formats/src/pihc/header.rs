//! PIHC header reader. The 0x10 field is a pre-archive length, not necessarily a kernel.
//!
//! A valid header proves only that the magic matches and that the archive offset lies
//! inside the package. It does not establish package authenticity, flash coverage or
//! the board.
use crate::magic;
use nyra_fw_core::{FwError, Result};

pub const HEADER_SIZE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PihcHeader {
    pub pre_archive_length: usize,
    pub archive_offset: usize,
    pub pre_archive_is_squashfs: bool,
}

impl PihcHeader {
    pub fn parse(package: &[u8]) -> Result<Self> {
        if !package.starts_with(magic::PIHC) {
            return Err(FwError::Unsupported(
                "unsupported input: currently only PIHC is implemented".into(),
            ));
        }
        // The magic matches, so a short input is a damaged PIHC input, not another format.
        if package.len() < HEADER_SIZE {
            return Err(FwError::Invalid(format!(
                "truncated PIHC header: {} of {HEADER_SIZE} bytes",
                package.len()
            )));
        }
        let pre_archive_length =
            u32::from_le_bytes([package[0x10], package[0x11], package[0x12], package[0x13]])
                as usize;
        let archive_offset = pre_archive_length
            .checked_add(HEADER_SIZE)
            .ok_or_else(|| FwError::Invalid("PIHC archive offset overflow".into()))?;
        if archive_offset <= HEADER_SIZE || archive_offset >= package.len() {
            return Err(FwError::Invalid(
                "PIHC archive offset is outside package".into(),
            ));
        }
        Ok(Self {
            pre_archive_length,
            archive_offset,
            pre_archive_is_squashfs: package[HEADER_SIZE..archive_offset]
                .starts_with(magic::SQUASHFS),
        })
    }

    pub fn pre_archive<'a>(&self, package: &'a [u8]) -> &'a [u8] {
        package
            .get(HEADER_SIZE..self.archive_offset)
            .unwrap_or_default()
    }

    pub fn archive<'a>(&self, package: &'a [u8]) -> &'a [u8] {
        package.get(self.archive_offset..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic/pihc-phase01.pkg");

    #[test]
    fn parses_the_fixture_without_claiming_board_identity() {
        let header = PihcHeader::parse(FIXTURE).unwrap();
        assert_eq!(header.archive_offset, 640);
        assert_eq!(header.pre_archive_length, 128);
    }

    #[test]
    fn separates_damaged_pihc_from_other_formats() {
        assert!(matches!(
            PihcHeader::parse(b"wrong"),
            Err(FwError::Unsupported(_))
        ));
        assert!(matches!(
            PihcHeader::parse(b"PIHC"),
            Err(FwError::Invalid(_))
        ));
        assert!(matches!(
            PihcHeader::parse(&[0; 520]),
            Err(FwError::Unsupported(_))
        ));
        let mut bytes = vec![0; 513];
        bytes[..4].copy_from_slice(b"PIHC");
        bytes[0x10..0x14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PihcHeader::parse(&bytes).is_err());
        bytes[0x10..0x14].copy_from_slice(&0u32.to_le_bytes());
        assert!(PihcHeader::parse(&bytes).is_err());
    }

    #[test]
    fn carves_pre_archive_squashfs() {
        let mut bytes = vec![0; 518];
        bytes[..4].copy_from_slice(b"PIHC");
        bytes[16..20].copy_from_slice(&4u32.to_le_bytes());
        bytes[512..516].copy_from_slice(b"hsqs");
        let header = PihcHeader::parse(&bytes).expect("test header");
        assert_eq!(header.archive_offset, 516);
        assert!(header.pre_archive_is_squashfs);
    }
}
