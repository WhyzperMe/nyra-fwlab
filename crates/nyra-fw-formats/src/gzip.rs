//! Strict, bounded decoding of one gzip member.
use crate::magic;
use flate2::bufread::GzDecoder;
use nyra_fw_core::{FwError, Limits, Result};
use std::io::Read;

pub fn decode(raw: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    limits.check_input(raw.len() as u64)?;
    limits.check_entry(raw.len() as u64, 0)?;
    let max = limits.max_entry_bytes.min(limits.max_total_output_bytes);
    let (decoded, consumed) = decode_prefix(raw, max)?;
    if consumed != raw.len() {
        return Err(FwError::Invalid(
            "trailing data or multiple gzip members".into(),
        ));
    }
    Ok(decoded)
}

/// Decode exactly one gzip member at the start of `raw`, which may be followed by
/// unrelated bytes. Returns the payload and the number of bytes the member
/// occupies, after CRC32 and ISIZE validation. Output beyond `max_output` is a
/// limit error.
pub fn decode_prefix(raw: &[u8], max_output: u64) -> Result<(Vec<u8>, usize)> {
    decode_prefix_metered(raw, max_output, &mut DecodeWork::default())
}

#[derive(Default)]
pub(crate) struct DecodeWork {
    pub(crate) input: u64,
    pub(crate) output: u64,
}

pub(crate) fn decode_prefix_metered(
    raw: &[u8],
    max_output: u64,
    work: &mut DecodeWork,
) -> Result<(Vec<u8>, usize)> {
    work.input = raw.len().min(65536) as u64;
    let flags = *raw
        .get(3)
        .ok_or_else(|| FwError::Invalid("truncated gzip header".into()))?;
    if !raw.starts_with(magic::GZIP_DEFLATE) || flags & 0xe0 != 0 {
        return Err(FwError::Invalid("invalid gzip header".into()));
    }
    // Validate optional field bounds before the decoder copies header metadata.
    let header = &raw[..raw.len().min(65536)];
    let mut offset = 10;
    if flags & 4 != 0 {
        let length = header
            .get(10..12)
            .ok_or_else(|| FwError::Invalid("truncated gzip extra field".into()))?;
        offset = 12 + u16::from_le_bytes([length[0], length[1]]) as usize;
    }
    for mask in [8, 16] {
        if flags & mask != 0 {
            let length = header
                .get(offset..)
                .and_then(|tail| tail.iter().position(|&byte| byte == 0))
                .ok_or_else(|| FwError::Invalid("unbounded or truncated gzip metadata".into()))?;
            offset += length + 1;
        }
    }
    if offset + usize::from(flags & 2 != 0) * 2 > header.len() {
        return Err(FwError::Invalid("gzip header exceeds its bounds".into()));
    }
    let mut decoded = Vec::new();
    let mut rest = raw;
    let mut decoder = GzDecoder::new(&mut rest);
    let result = decoder
        .by_ref()
        .take(max_output.saturating_add(1))
        .read_to_end(&mut decoded)
        .map_err(|error| {
            FwError::Verification(format!(
                "gzip decompression or trailer validation failed: {error}"
            ))
        });
    drop(decoder);
    work.input = work.input.max((raw.len() - rest.len()) as u64);
    work.output = decoded.len() as u64;
    result?;
    if decoded.len() as u64 > max_output {
        return Err(FwError::Limit("gzip decoded member exceeds limit".into()));
    }
    Ok((decoded, raw.len() - rest.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    #[test]
    fn rejects_bad_crc_trailing_members_and_output_overflow() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&[1; 1024]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(decode(&compressed, &Limits::default()).unwrap(), [1; 1024]);
        let mut damaged = compressed.clone();
        let crc = damaged.len() - 8;
        damaged[crc] ^= 1;
        assert!(decode(&damaged, &Limits::default()).is_err());
        assert!(
            decode(
                &[compressed.as_slice(), &compressed].concat(),
                &Limits::default()
            )
            .is_err()
        );
        let (payload, consumed) =
            decode_prefix(&[compressed.as_slice(), b"tail"].concat(), 4096).unwrap();
        assert_eq!((payload.len(), consumed), (1024, compressed.len()));
        assert!(matches!(
            decode_prefix(&compressed, 10),
            Err(FwError::Limit(_))
        ));
        let tiny = Limits {
            max_total_output_bytes: 10,
            ..Limits::default()
        };
        assert!(matches!(decode(&compressed, &tiny), Err(FwError::Limit(_))));
    }
}
