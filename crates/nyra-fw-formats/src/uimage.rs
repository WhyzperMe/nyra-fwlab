//! Legacy U-Boot image header and payload integrity checks.
use serde::Serialize;

pub const HEADER_SIZE: usize = 64;

#[derive(Debug, Serialize)]
pub struct Image {
    pub payload_bytes: u32,
    pub load_address: u32,
    pub entry_point: u32,
    pub os: u8,
    pub architecture: u8,
    pub image_type: u8,
    pub compression: u8,
}

pub fn inspect(bytes: &[u8]) -> Option<Image> {
    validate(bytes).ok()
}

/// Validate a legacy uImage; the error names the first failed check. The payload
/// CRC is computed only after the header and payload bounds have passed.
pub fn validate(bytes: &[u8]) -> Result<Image, &'static str> {
    validate_with_budget(bytes, |_| true)
}

pub(crate) fn validate_with_budget(
    bytes: &[u8],
    charge: impl FnOnce(u64) -> bool,
) -> Result<Image, &'static str> {
    let header: &[u8; HEADER_SIZE] = bytes
        .get(..HEADER_SIZE)
        .and_then(|head| head.try_into().ok())
        .ok_or("uimage_header_present")?;
    let read = |offset: usize| -> u32 {
        u32::from_be_bytes([
            header[offset],
            header[offset + 1],
            header[offset + 2],
            header[offset + 3],
        ])
    };
    if read(0) != 0x27051956 {
        return Err("uimage_magic");
    }
    let payload_bytes = read(12);
    let payload = usize::try_from(payload_bytes)
        .ok()
        .and_then(|length| bytes.get(HEADER_SIZE..HEADER_SIZE.checked_add(length)?))
        .filter(|payload| !payload.is_empty())
        .ok_or("uimage_payload_within_input")?;
    let mut crc_header = *header;
    crc_header[4..8].fill(0);
    if crc32fast::hash(&crc_header) != read(4) {
        return Err("uimage_header_crc32");
    }
    if !charge(u64::from(payload_bytes)) {
        return Err("uimage_payload_budget");
    }
    if crc32fast::hash(payload) != read(24) {
        return Err("uimage_payload_crc32");
    }
    Ok(Image {
        payload_bytes,
        load_address: read(16),
        entry_point: read(20),
        os: header[28],
        architecture: header[29],
        image_type: header[30],
        compression: header[31],
    })
}
