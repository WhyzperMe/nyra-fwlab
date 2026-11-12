//! Human-readable reports derived exclusively from the typed manifest.
use nyra_fw_core::FirmwareManifest;

pub fn summary(m: &FirmwareManifest) -> String {
    let s = &m.summary;
    format!(
        "# Firmware recovery report\n\nInput SHA-256: `{}`\n\nFormat: `{}`\n\n| Measure | Value |\n| --- | ---: |\n| Local-header signatures seen | {} |\n| Directory placeholders | {} |\n| Eligible members | {} |\n| Original CRC-valid | {} |\n| Recovered CRC-valid | {} |\n| Failed eligible | {} |\n| Unsupported members | {} |\n| Duplicate names | {} |\n| Recovered bytes | {} |\n\n## Cautions\n\n{}\n",
        m.source.sha256,
        m.detected_format,
        s.signatures_seen,
        s.directory_entries,
        s.eligible_entries,
        s.original_crc_ok,
        s.recovered_crc_ok,
        s.failed_entries,
        s.unsupported_entries,
        s.duplicate_names,
        s.bytes_recovered,
        m.warnings
            .iter()
            .map(|w| format!("- {w}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}
