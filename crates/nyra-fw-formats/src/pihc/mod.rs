//! HiChip PIHC reader and empirically validated SSC338Q recovery hypothesis.
pub mod crypto;
pub mod header;
pub mod recovery;
pub mod verify;

pub use crypto::{CryptoVariant, KeyMode};
pub use header::PihcHeader;
pub use recovery::{RecoveredFile, RecoveryOptions, RecoveryResult, recover};
