//! Deterministic key of an offline run, scoped by source, release and options.
use crate::sha256_hex;

pub fn cache_key(source_sha256: &str, format_version: &str, options: &str) -> String {
    sha256_hex(format!("nyra-fw:v1\0{source_sha256}\0{format_version}\0{options}").as_bytes())
}
