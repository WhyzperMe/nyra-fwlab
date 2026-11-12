//! Checked byte ranges retain their source and coordinate space.
//!
//! Identities describe provenance established by the caller; constructing a view
//! does not hash or authenticate its bytes. Ranges cannot be reapplied to another
//! buffer, and decoded coordinates cannot be used as original-input coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Original<'a> {
    pub sha256: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedGzip<'a> {
    pub source_sha256: &'a str,
    pub candidate_id: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ByteSource<'a, S> {
    bytes: &'a [u8],
    identity: S,
}

impl<'a, S: Copy> ByteSource<'a, S> {
    pub fn new(bytes: &'a [u8], identity: S) -> Self {
        Self { bytes, identity }
    }

    pub fn range(self, start: u64, length: u64) -> Option<CheckedRange<'a, S>> {
        let end = start.checked_add(length)?;
        let bytes = self
            .bytes
            .get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)?;
        Some(CheckedRange {
            bytes,
            identity: self.identity,
            start,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CheckedRange<'a, S> {
    bytes: &'a [u8],
    identity: S,
    start: u64,
}

impl<'a, S: Copy> CheckedRange<'a, S> {
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    pub fn identity(self) -> S {
        self.identity
    }
    pub fn start(self) -> u64 {
        self.start
    }
    pub fn length(self) -> u64 {
        self.bytes.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_overflow_and_source_binding() {
        let bytes = b"abcdef";
        let source = ByteSource::new(
            bytes,
            Original {
                sha256: "caller-established",
            },
        );
        assert!(source.range(u64::MAX, 1).is_none());
        assert!(source.range(5, 2).is_none());
        assert_eq!(source.range(6, 0).unwrap().bytes(), b"");
        let range = source.range(2, 3).unwrap();
        assert_eq!(range.bytes(), b"cde");
        assert_eq!((range.start(), range.length()), (2, 3));
        assert_eq!(range.identity().sha256, "caller-established");
    }
}
