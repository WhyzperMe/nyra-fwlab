//! Deterministic, explainable triage. No LLM calls, runtime guessing or execution.
use crate::binary::BinaryReport;
use serde::{Deserialize, Serialize};

const LENS: &[&str] = &[
    "hi_af_",
    "hi_ptz_motor_af",
    "zoom",
    "focus",
    "autofocus",
    "lens",
    "motor",
];
const SENSOR: &[&str] = &["imx415", "sensor", "isp", "vif", "vpe", "mipi"];
const HARDWARE: &[&str] = &["/dev/i2c", "/dev/spi", "gpio", "ssc338"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedBinary {
    pub source: String,
    pub sha256: String,
    pub priority_score: u32,
    pub categories: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub schema_version: u32,
    pub scanned_binaries: usize,
    pub prioritized: Vec<PrioritizedBinary>,
    pub method: String,
}

fn label(b: &BinaryReport, needles: &[&str]) -> (usize, usize) {
    let symbols = b
        .symbols
        .iter()
        .filter(|s| {
            needles
                .iter()
                .any(|n| s.name.to_ascii_lowercase().contains(n))
        })
        .count();
    let strings = b
        .strings
        .iter()
        .filter(|s| needles.iter().any(|n| s.to_ascii_lowercase().contains(n)))
        .count();
    (symbols, strings)
}

pub fn prioritize(binaries: &[BinaryReport]) -> TriageReport {
    let mut prioritized = Vec::new();
    for b in binaries {
        let mut score = 0u32;
        let mut categories = Vec::new();
        let mut evidence = Vec::new();
        for (category, needles, weight) in [
            ("lens_control", LENS, 8u32),
            ("imaging_pipeline", SENSOR, 4u32),
            ("hardware_io", HARDWARE, 5u32),
        ] {
            let (symbols, strings) = label(b, needles);
            if symbols + strings == 0 {
                continue;
            }
            categories.push(category.to_owned());
            let contribution = (symbols.min(20) as u32)
                .saturating_mul(weight)
                .saturating_add((strings.min(20) as u32).saturating_mul(weight / 2));
            score = score.saturating_add(contribution);
            evidence.push(format!(
                "{category}: {symbols} matching symbols; {strings} matching strings"
            ));
        }
        if b.source.ends_with("/ipc_server") || b.source == "ipc_server" {
            categories.push("known_ipc_entrypoint".into());
            evidence.push("Filename matches ipc_server (not proof of active runtime use)".into());
            score = score.saturating_add(20);
        }
        if b.truncated {
            evidence.push("ELF symbol or string collection was truncated".into());
        }
        prioritized.push(PrioritizedBinary {
            source: b.source.clone(),
            sha256: b.sha256.clone(),
            priority_score: score,
            categories,
            evidence,
        });
    }
    prioritized.sort_by(|a, b| {
        b.priority_score
            .cmp(&a.priority_score)
            .then(a.source.cmp(&b.source))
    });
    TriageReport {
        schema_version: 1, scanned_binaries: prioritized.len(), prioritized,
        method: "Capped weighted counts of observed ELF symbols and ASCII strings. A ranking for manual review, not a hardware assertion, risk score or execution trace.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryReport, ElfSecurity, SymbolInfo};
    fn sample(name: &str, sym: &str) -> BinaryReport {
        BinaryReport {
            source: name.into(),
            sha256: "0".repeat(64),
            file_type: "other".into(),
            machine: 40,
            word_size: 32,
            little_endian: true,
            entry_point: 0,
            interpreter: None,
            soname: None,
            libraries: vec![],
            rpaths: vec![],
            runpaths: vec![],
            symbols: vec![SymbolInfo {
                name: sym.into(),
                address: 1,
                size: 4,
                kind: "function".into(),
            }],
            strings: vec![],
            string_hits: vec![],
            truncated: false,
            security: ElfSecurity::default(),
        }
    }
    #[test]
    fn lens_binary_first_deterministically() {
        let a = sample("z", "plain");
        let b = sample("a", "HI_AF_I2cRunZoom");
        let x = prioritize(&[a.clone(), b.clone()]);
        let y = prioritize(&[b, a]);
        assert_eq!(x.prioritized[0].source, "a");
        assert_eq!(
            x.prioritized.iter().map(|v| &v.source).collect::<Vec<_>>(),
            y.prioritized.iter().map(|v| &v.source).collect::<Vec<_>>()
        );
    }
}
