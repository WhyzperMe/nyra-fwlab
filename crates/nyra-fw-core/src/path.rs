//! Portable names for firmware-controlled workspace paths.

pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_DEPTH: usize = 36;

pub fn is_safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.split('/').count() <= MAX_DEPTH
        && path.split('/').all(|part| {
            !part.is_empty()
                && part.len() <= 255
                && !part.ends_with(['.', ' '])
                && part.bytes().all(|byte| {
                    (32..=126).contains(&byte)
                        && !matches!(byte, b'<' | b'>' | b'"' | b'|' | b'?' | b'*' | b'\\' | b':')
                })
                && !matches!(
                    part.split('.')
                        .next()
                        .unwrap_or_default()
                        .trim_end()
                        .to_ascii_uppercase()
                        .as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "CONIN$"
                        | "CONOUT$"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
        })
}

#[cfg(test)]
mod tests {
    use super::is_safe_relative;

    #[test]
    fn paths_reject_escape_aliases_and_device_names() {
        for path in [
            "../bad",
            "a/../bad",
            "/root",
            "a\\b",
            "C:foo",
            "a/./b",
            "",
            "a//b",
            "NUL.txt",
            "dir/COM1",
            "trailing.",
            "trailing ",
        ] {
            assert!(!is_safe_relative(path), "accepted {path:?}");
        }
        assert!(is_safe_relative("recovered/update/mnt/mtd/ipc/ipc_server"));
        assert!(!is_safe_relative(&"a/".repeat(40)));
    }
}
