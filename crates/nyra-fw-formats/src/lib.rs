//! Firmware container readers. Offline and read-only with respect to inputs.
#![forbid(unsafe_code)]

pub mod archive;
mod bytes;
pub mod candidates;
pub mod central;
pub mod gzip;
pub mod input;
pub mod magic;
pub mod pihc;
pub mod squashfs;
pub mod tar;
pub mod uimage;
pub mod zip;
