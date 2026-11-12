//! Hardware references observed in ELF strings, never hardware assertions.
use crate::binary::BinaryReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareReference {
    pub source: String,
    pub text: String,
    pub kind: String,
    pub evidence: String,
}

pub fn references(reports: &[BinaryReport]) -> Vec<HardwareReference> {
    let mut out = Vec::new();
    for b in reports {
        for s in &b.strings {
            let lower = s.to_ascii_lowercase();
            let kind = if lower.contains("/dev/i2c") {
                "i2c_device_path"
            } else if lower.contains("imx415") {
                "sensor_reference"
            } else if lower.contains("gpio") {
                "gpio_reference"
            } else if lower.contains("ssc338") {
                "soc_reference"
            } else {
                continue;
            };
            out.push(HardwareReference {
                source: b.source.clone(),
                text: s.clone(),
                kind: kind.into(),
                evidence: "raw embedded string; no runtime validation".into(),
            });
        }
    }
    out
}
