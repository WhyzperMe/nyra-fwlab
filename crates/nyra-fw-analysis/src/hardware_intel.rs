//! Stage 04: bounded, evidence-oriented hardware inventory.
//!
//! These are **observations of static bytes**, not facts about a connected device.
//! This module never executes firmware or accesses a device node.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::binary::BinaryReport;

pub const MAX_INVENTORY: usize = 20_000;
pub const MAX_OBSERVATIONS: usize = 5_000;
pub const MAX_CONFIG_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    KernelModule,
    SensorBlob,
    LensConfiguration,
    BootConfiguration,
    InitScript,
    SharedLibrary,
    ExecutableCandidate,
    DeviceTree,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub path: String,
    pub origin: String,
    pub kind: ComponentKind,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    SocIdentifier,
    SensorIdentifier,
    I2cDevicePath,
    MotorSymbol,
    LensSymbol,
    ConfigurationKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    pub kind: ObservationKind,
    pub value: String,
    pub source: String,
    pub evidence: String,
    pub file_offset: Option<u64>,
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIndex {
    pub schema_version: u32,
    pub components: Vec<Component>,
    pub observations: Vec<Observation>,
    pub component_truncated: bool,
    pub observation_truncated: bool,
    pub model_verified_on_hardware: bool,
    pub warning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModuleEvidence {
    pub path: String,
    pub vermagic: Option<String>,
    pub dependencies: Vec<String>,
    pub license: Option<String>,
    pub method: String,
}

pub const MAX_MODULE_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Extract only conventional NUL-delimited Linux module info fields. The
/// presence of these bytes does not establish that a module can be loaded or
/// that it is signed, trusted, or compatible with the chosen target kernel.
pub fn module_metadata(path: &str, bytes: &[u8]) -> Option<KernelModuleEvidence> {
    if bytes.len() > MAX_MODULE_SCAN_BYTES {
        return None;
    }
    let mut vermagic = None;
    let mut license = None;
    let mut dependencies = BTreeSet::new();
    for field in bytes.split(|byte| *byte == 0) {
        if field.len() > 240 {
            continue;
        }
        let Ok(text) = std::str::from_utf8(field) else {
            continue;
        };
        if let Some(v) = text.strip_prefix("vermagic=") {
            if !v.is_empty()
                && v.len() <= 160
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b" ._+-".contains(&c))
            {
                vermagic.get_or_insert_with(|| v.to_owned());
            }
        } else if let Some(v) = text.strip_prefix("license=") {
            if let Some(name) = safe_identifier(v) {
                license.get_or_insert(name);
            }
        } else if let Some(v) = text.strip_prefix("depends=") {
            for dependency in v.split(',').take(64) {
                if let Some(name) = safe_identifier(dependency) {
                    dependencies.insert(name);
                }
            }
        }
    }
    if vermagic.is_none() && license.is_none() && dependencies.is_empty() {
        return None;
    }
    Some(KernelModuleEvidence {
        path: path.into(),
        vermagic,
        dependencies: dependencies.into_iter().collect(),
        license,
        method: "observed_nul_delimited_modinfo_bytes_not_kernel_abi_verification".into(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensWorklist {
    pub schema_version: u32,
    pub candidate_binaries: Vec<String>,
    pub observed_i2c_paths: Vec<String>,
    pub relevant_function_symbols: Vec<String>,
    pub observed_configuration_keys: Vec<String>,
    pub controller_model: Option<String>,
    pub i2c_slave_address: Option<u16>,
    pub verified_mechanical_limits: bool,
    pub mandatory_validation: Vec<String>,
}

fn contains_any(s: &str, terms: &[&str]) -> bool {
    terms.iter().any(|part| s.contains(part))
}

/// Conservative path classification. File names alone establish *candidates*,
/// not actual active boot modules or a device-specific sensor configuration.
pub fn classify_path(path: &str) -> Option<ComponentKind> {
    let p = path.to_ascii_lowercase();
    if p.ends_with(".ko") {
        return Some(ComponentKind::KernelModule);
    }
    if p.ends_with(".dtb") || p.ends_with(".dtbo") {
        return Some(ComponentKind::DeviceTree);
    }
    if p.contains("/sensor/") && p.ends_with(".bin") {
        return Some(ComponentKind::SensorBlob);
    }
    if p.contains("zoomfocus") && (p.ends_with(".ini") || p.ends_with(".cfg")) {
        return Some(ComponentKind::LensConfiguration);
    }
    if p.contains("/etc/init.d/") || p.ends_with("/etc/inittab") || p.ends_with("/etc/rc.local") {
        return Some(ComponentKind::InitScript);
    }
    if p.contains("/bootconfig/") || p.ends_with("/bootargs") || p.ends_with("/cmdline") {
        return Some(ComponentKind::BootConfiguration);
    }
    if p.contains(".so.") || p.ends_with(".so") {
        return Some(ComponentKind::SharedLibrary);
    }
    if p.ends_with("/ipc_server") || p.ends_with("/onvif") {
        return Some(ComponentKind::ExecutableCandidate);
    }
    None
}

/// Restrict extracted identifiers to a minimal ASCII vocabulary. In particular,
/// never include arbitrary firmware messages, script bodies or secret values.
fn safe_identifier(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    if !value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c))
    {
        return None;
    }
    Some(value.to_owned())
}

fn identifier_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.')))
        .filter(|s| !s.is_empty() && s.len() <= 128)
}

/// Static evidence from ELF symbol and mapped printable-string hits.
/// Device path strings are not evidence that a slave was present at runtime.
pub fn binary_observations(reports: &[BinaryReport]) -> Vec<Observation> {
    let mut rows = Vec::new();
    let mut unique = BTreeSet::new();
    'bounded: for binary in reports {
        for symbol in &binary.symbols {
            if rows.len() >= MAX_OBSERVATIONS {
                break 'bounded;
            }
            if symbol.kind != "function" {
                continue;
            }
            let lower = symbol.name.to_ascii_lowercase();
            let kind = if contains_any(
                &lower,
                &["hi_af_i2c", "hi_ptz_motor", "i2crunzoom", "i2crunfocus"],
            ) {
                ObservationKind::MotorSymbol
            } else if contains_any(&lower, &["zoom", "focus", "lens", "autofocus"]) {
                ObservationKind::LensSymbol
            } else {
                continue;
            };
            let Some(value) = safe_identifier(&symbol.name) else {
                continue;
            };
            let key = (
                binary.source.as_str(),
                kind.clone(),
                value.clone(),
                Some(symbol.address),
            );
            if !unique.insert(key) {
                continue;
            }
            rows.push(Observation {
                kind,
                value,
                source: binary.source.clone(),
                evidence: "elf_symbol_table".into(),
                file_offset: None,
                virtual_address: Some(symbol.address),
            });
        }
        for hit in &binary.string_hits {
            for token in identifier_tokens(&hit.text) {
                if rows.len() >= MAX_OBSERVATIONS {
                    break 'bounded;
                }
                let lower = token.to_ascii_lowercase();
                let (kind, value) = if lower.strip_prefix("/dev/i2c-").is_some_and(|suffix| {
                    (1..=3).contains(&suffix.len()) && suffix.bytes().all(|b| b.is_ascii_digit())
                }) {
                    (ObservationKind::I2cDevicePath, lower)
                } else if lower.contains("imx415") {
                    (ObservationKind::SensorIdentifier, "imx415".into())
                } else if lower.contains("ssc338q") {
                    (ObservationKind::SocIdentifier, "ssc338q".into())
                } else {
                    continue;
                };
                let key = (
                    binary.source.as_str(),
                    kind.clone(),
                    value.clone(),
                    Some(hit.file_offset),
                );
                if !unique.insert(key) {
                    continue;
                }
                rows.push(Observation {
                    kind,
                    value,
                    source: binary.source.clone(),
                    evidence: "elf_printable_bytes".into(),
                    file_offset: Some(hit.file_offset),
                    virtual_address: hit.virtual_address,
                });
            }
        }
    }
    rows.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then(a.kind.cmp(&b.kind))
            .then(a.value.cmp(&b.value))
            .then(a.file_offset.cmp(&b.file_offset))
    });
    rows.truncate(MAX_OBSERVATIONS);
    rows
}

/// Config key presence only: values are intentionally not exported. Allowlist
/// protects against unintentionally copying credentials into Claude workspaces.
pub fn config_key_observations(source: &str, bytes: &[u8]) -> Vec<Observation> {
    if bytes.len() > MAX_CONFIG_BYTES || bytes.contains(&0) {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut keys = BTreeSet::new();
    let mut result = Vec::new();
    for line in text.lines().take(4_096) {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let Some((key, _private_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.len() > 64
            || !key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
        {
            continue;
        }
        if !contains_any(
            &key,
            &[
                "zoom", "focus", "lens", "afzoom", "motor", "sensor", "i2c", "gpio",
            ],
        ) {
            continue;
        }
        if !keys.insert(key.clone()) {
            continue;
        }
        result.push(Observation {
            kind: ObservationKind::ConfigurationKey,
            value: key,
            source: source.into(),
            evidence: "configuration_key_only_value_redacted".into(),
            file_offset: None,
            virtual_address: None,
        });
        if result.len() == 128 {
            break;
        }
    }
    result
}

pub fn build_index(
    mut components: Vec<Component>,
    mut observations: Vec<Observation>,
) -> HardwareIndex {
    components.sort_by(|a, b| a.path.cmp(&b.path).then(a.origin.cmp(&b.origin)));
    components.dedup_by(|a, b| a.path == b.path && a.origin == b.origin);
    observations.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then(a.kind.cmp(&b.kind))
            .then(a.value.cmp(&b.value))
            .then(a.file_offset.cmp(&b.file_offset))
    });
    observations.dedup_by(|a, b| {
        a.source == b.source
            && a.kind == b.kind
            && a.value == b.value
            && a.file_offset == b.file_offset
    });
    let component_truncated = components.len() > MAX_INVENTORY;
    // A full boundary means the upstream bounded scanner might have omitted
    // additional observations, so conservatively report truncation.
    let observation_truncated = observations.len() >= MAX_OBSERVATIONS;
    components.truncate(MAX_INVENTORY);
    observations.truncate(MAX_OBSERVATIONS);
    HardwareIndex {
        schema_version: 1, components, observations, component_truncated, observation_truncated,
        model_verified_on_hardware: false,
        warning: "All observations originate from firmware bytes or file names. They cannot confirm the physical board, electrical wiring, active software paths or safe lens movement.".into(),
    }
}

/// Filenames may provide useful sensor/SoC *labels*, but do not verify a
/// populated device or that a binary is loaded at runtime.
pub fn filename_observations(components: &[Component]) -> Vec<Observation> {
    let mut observations = Vec::new();
    for component in components {
        let lower = component.path.to_ascii_lowercase();
        let (kind, name) =
            if component.kind == ComponentKind::SensorBlob && lower.contains("imx415") {
                (ObservationKind::SensorIdentifier, "imx415")
            } else if lower.contains("ssc338q") {
                (ObservationKind::SocIdentifier, "ssc338q")
            } else {
                continue;
            };
        observations.push(Observation {
            kind,
            value: name.into(),
            source: component.path.clone(),
            evidence: "firmware_filename_not_physical_verification".into(),
            file_offset: None,
            virtual_address: None,
        });
    }
    observations
}

pub fn lens_worklist(index: &HardwareIndex) -> LensWorklist {
    let mut binaries = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut functions = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for record in &index.observations {
        match record.kind {
            ObservationKind::I2cDevicePath => {
                paths.insert(record.value.clone());
            }
            ObservationKind::MotorSymbol | ObservationKind::LensSymbol => {
                functions.insert(record.value.clone());
                binaries.insert(record.source.clone());
            }
            ObservationKind::ConfigurationKey => {
                keys.insert(record.value.clone());
            }
            _ => {}
        }
    }
    LensWorklist {
        schema_version: 1,
        candidate_binaries: binaries.into_iter().collect(),
        observed_i2c_paths: paths.into_iter().collect(),
        relevant_function_symbols: functions.into_iter().take(1_000).collect(),
        observed_configuration_keys: keys.into_iter().collect(),
        controller_model: None,
        i2c_slave_address: None,
        verified_mechanical_limits: false,
        mandatory_validation: vec![
            "Trace verified call sites and arguments before assigning any register semantics"
                .into(),
            "Confirm I2C device path, address and protocol on stationary hardware".into(),
            "Identify the actual motor controller from board markings or datasheet".into(),
            "Determine physical end stops, homing, current limit and fault/timeout behavior".into(),
            "Distinguish optical zoom from digital zoom and confirm autofocus implementation"
                .into(),
        ],
    }
}

/// Frequency summary is deterministic and never reinterpreted as certainty.
pub fn category_counts(components: &[Component]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for component in components {
        let key = format!("{:?}", component.kind);
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryReport, ElfSecurity, StringHit, SymbolInfo};

    fn fake_report() -> BinaryReport {
        BinaryReport {
            source: "mnt/mtd/ipc/ipc_server".into(),
            sha256: "0".repeat(64),
            file_type: "executable".into(),
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
                name: "HI_AF_I2cRunZoom".into(),
                address: 0x96e54,
                size: 144,
                kind: "function".into(),
            }],
            strings: vec![],
            string_hits: vec![StringHit {
                file_offset: 500,
                virtual_address: Some(0xabc),
                text: "prefix /dev/i2c-2 suffix IMX415".into(),
            }],
            truncated: false,
            security: ElfSecurity::default(),
        }
    }

    #[test]
    fn extracts_only_observed_i2c_path_and_preserves_offsets() {
        let observations = binary_observations(&[fake_report()]);
        assert!(
            observations
                .iter()
                .any(|row| row.kind == ObservationKind::I2cDevicePath
                    && row.value == "/dev/i2c-2"
                    && row.file_offset == Some(500))
        );
        assert!(
            observations
                .iter()
                .any(|row| row.kind == ObservationKind::SensorIdentifier)
        );
        assert!(
            observations
                .iter()
                .any(|row| row.kind == ObservationKind::MotorSymbol)
        );
    }

    #[test]
    fn config_parser_redacts_values_and_rejects_binary_data() {
        let data = b"password=supersecret\nzoomfocus=TRUE\nfocus_max=920\nfoo=x\n";
        let found = config_key_observations("config.ini", data);
        assert_eq!(found.len(), 2);
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains("supersecret") && !json.contains("920") && !json.contains("TRUE"));
        assert!(config_key_observations("x", b"motor=1\0secret").is_empty());
    }

    #[test]
    fn kernel_modinfo_is_bounded_and_does_not_claim_abi_compatibility() {
        let bytes = b"random\0vermagic=4.9.84 SMP mod_unload ARMv7\0depends=foo,bar\0license=GPL\0";
        let info = module_metadata("lib/motor.ko", bytes).expect("module metadata");
        assert_eq!(
            info.vermagic.as_deref(),
            Some("4.9.84 SMP mod_unload ARMv7")
        );
        assert_eq!(info.dependencies, vec!["bar", "foo"]);
        assert!(info.method.contains("not_kernel_abi_verification"));
        assert!(module_metadata("x.ko", b"random\0").is_none());
    }

    #[test]
    fn lens_worklist_leaves_unknown_hardware_unknown() {
        let index = build_index(vec![], binary_observations(&[fake_report()]));
        let work = lens_worklist(&index);
        assert!(work.observed_i2c_paths.contains(&"/dev/i2c-2".into()));
        assert!(work.controller_model.is_none() && work.i2c_slave_address.is_none());
        assert!(!work.verified_mechanical_limits);
    }

    #[test]
    fn path_classification_does_not_call_png_a_motor_driver() {
        assert_eq!(classify_path("mnt/mtd/ipc/web/images/zoomin_de.jpg"), None);
        assert_eq!(
            classify_path("mnt/mtd/ipc/sensor/IMX415_day.bin"),
            Some(ComponentKind::SensorBlob)
        );
        assert_eq!(
            classify_path("lib/modules/motor.ko"),
            Some(ComponentKind::KernelModule)
        );
    }
}
