//! Bounds-checked fixed-width integer reads. Every function returns `None` instead of
//! panicking when the range lies outside the slice, so parsers can use `?`.

fn array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

pub(crate) fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    array(bytes, at).map(u16::from_le_bytes)
}

pub(crate) fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    array(bytes, at).map(u32::from_le_bytes)
}

pub(crate) fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    array(bytes, at).map(u64::from_le_bytes)
}

pub(crate) fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    array(bytes, at).map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_byte_orders_and_refuses_out_of_range() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(le_u16(&bytes, 0), Some(0x0201));
        assert_eq!(le_u32(&bytes, 0), Some(0x0403_0201));
        assert_eq!(be_u32(&bytes, 0), Some(0x0102_0304));
        assert_eq!(le_u64(&bytes, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(le_u32(&bytes, 5), None);
        assert_eq!(le_u16(&bytes, usize::MAX), None);
        assert_eq!(le_u64(&[], 0), None);
    }
}
