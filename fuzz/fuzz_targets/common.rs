use nyra_fw_core::Limits;

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

pub fn is_bounded(data: &[u8]) -> bool {
    data.len() <= MAX_INPUT_BYTES
}

#[allow(dead_code)] // Only the container fuzzers need per-input parser limits.
pub fn limits() -> Limits {
    Limits {
        max_input_bytes: MAX_INPUT_BYTES as u64,
        max_entry_bytes: 256 * 1024,
        max_total_output_bytes: MAX_INPUT_BYTES as u64,
        max_entries: 256,
        max_path_bytes: 512,
        max_extra_field_bytes: 4096,
    }
}
