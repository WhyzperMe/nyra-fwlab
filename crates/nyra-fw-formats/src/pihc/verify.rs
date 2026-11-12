//! Bounded decompression and exact CRC32 validation of local ZIP members.
use crate::zip::LocalEntry;
use flate2::{Decompress, FlushDecompress, Status};
use nyra_fw_core::Limits;

pub fn decode_verified(payload: &[u8], entry: &LocalEntry, limits: &Limits) -> Option<Vec<u8>> {
    if payload.len() != entry.compressed_size
        || limits
            .check_entry(payload.len() as u64, entry.uncompressed_size as u64)
            .is_err()
    {
        return None;
    }
    let decoded = match entry.method {
        0 if payload.len() == entry.uncompressed_size
            && crc32fast::hash(payload) == entry.crc32 =>
        {
            return Some(payload.to_vec());
        }
        8 => {
            let mut decoder = Decompress::new(false);
            let mut content = Vec::new();
            content
                .try_reserve_exact(entry.uncompressed_size.checked_add(1)?)
                .ok()?;
            let status = decoder
                .decompress_vec(payload, &mut content, FlushDecompress::Finish)
                .ok()?;
            if status != Status::StreamEnd
                || decoder.total_in() != payload.len() as u64
                || decoder.total_out() != entry.uncompressed_size as u64
            {
                return None;
            }
            content
        }
        _ => return None,
    };
    if decoded.len() != entry.uncompressed_size || crc32fast::hash(&decoded) != entry.crc32 {
        return None;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;

    #[test]
    fn exact_deflate_with_crc_is_accepted() {
        let original = b"a perfectly normal firmware configuration, compressed and verified";
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(original).expect("encode");
        let compressed = enc.finish().expect("finish");
        let entry = LocalEntry {
            name: "config/example.ini".into(),
            header_offset: 0,
            data_offset: 0,
            compressed_size: compressed.len(),
            uncompressed_size: original.len(),
            crc32: crc32fast::hash(original),
            method: 8,
        };
        assert_eq!(
            decode_verified(&compressed, &entry, &Limits::default()).as_deref(),
            Some(original.as_slice())
        );
        let mut invalid = compressed;
        invalid.push(42);
        let mut entry2 = entry.clone();
        entry2.compressed_size = invalid.len();
        assert!(decode_verified(&invalid, &entry2, &Limits::default()).is_none());
        for length in 0..entry.compressed_size {
            let mut truncated = entry.clone();
            truncated.compressed_size = length;
            assert!(decode_verified(&invalid[..length], &truncated, &Limits::default()).is_none());
        }
    }

    #[test]
    fn oversized_member_rejected_before_decode() {
        let entry = LocalEntry {
            name: "config/example.ini".into(),
            header_offset: 0,
            data_offset: 0,
            compressed_size: 1,
            uncompressed_size: 1000,
            crc32: 0,
            method: 0,
        };
        let limits = Limits {
            max_entry_bytes: 10,
            ..Limits::default()
        };
        assert!(decode_verified(&[0], &entry, &limits).is_none());
    }
}
