//! Signature bytes shared by input dispatch and candidate discovery.
//!
//! One definition per format keeps `input::identify` and the candidate scanner from
//! drifting apart. A signature identifies a candidate only; it never identifies a
//! board, a vendor or a valid structure.

pub const PIHC: &[u8] = b"PIHC";
pub const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
/// HiChip variant of the local header, found inside PIHC packages.
pub const ZIP_LOCAL_HICHIP: &[u8] = b"PK\x03\x07";
pub const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
pub(crate) const ZIP_DESCRIPTOR: &[u8] = b"PK\x07\x08";
/// HiChip variant of the central header.
pub const ZIP_CENTRAL_HICHIP: &[u8] = b"PK\x01\x08";
pub const ZIP_END: &[u8] = b"PK\x05\x06";
/// HiChip variant of the end record.
pub const ZIP_END_HICHIP: &[u8] = b"PK\x05\x09";
/// First two bytes of any gzip member.
pub const GZIP: &[u8] = &[0x1f, 0x8b];
/// Gzip with the only defined compression method, DEFLATE.
pub const GZIP_DEFLATE: &[u8] = &[0x1f, 0x8b, 0x08];
pub const SQUASHFS: &[u8] = b"hsqs";
pub const SQUASHFS_BIG_ENDIAN: &[u8] = b"sqsh";
pub const UIMAGE: &[u8] = &[0x27, 0x05, 0x19, 0x56];
pub const ELF: &[u8] = b"\x7fELF";
pub const FDT: &[u8] = &[0xd0, 0x0d, 0xfe, 0xed];
pub const UBI_ERASE_COUNTER: &[u8] = b"UBI#";
pub const XZ: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0];
pub const BZIP2: &[u8] = b"BZh";
pub const ZSTD: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
/// bzip2 block header magic, found four bytes after the stream signature.
pub const BZIP2_BLOCK: &[u8] = &[0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
