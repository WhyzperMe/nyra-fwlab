//! Stage 04: static hardware, driver and lens evidence with explicit uncertainty.
//! Input bytes are treated as untrusted data; no firmware code is executed.
use std::path::Path;

use nyra_fw_analysis::{
    binary::BinaryReport,
    hardware_intel::{
        self, Component, ComponentKind, HardwareIndex, KernelModuleEvidence, LensWorklist,
        Observation,
    },
};
use nyra_fw_core::{FwError, Result, budget::RunBudget};
use nyra_fw_formats::archive::RecoveredFile;
use serde::{Deserialize, Serialize};

use crate::{files, report_writer::ReportWriter, rootfs, stage02::Stage02Manifest};

const MAX_CONFIGS: usize = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage04Manifest {
    pub schema_version: u32,
    pub source_sha256: String,
    pub source_kind: String,
    pub indexed_components: usize,
    pub indexed_module_metadata: usize,
    pub indexed_observations: usize,
    pub inventory_truncated: bool,
    pub observations_truncated: bool,
    pub motor_symbol_observations: usize,
    pub sensor_references: usize,
    pub i2c_path_references: usize,
    pub rootfs_state: String,
    pub reports: Vec<String>,
    pub verification_required: Vec<String>,
}

fn to_json<T: Serialize>(
    writer: &mut ReportWriter<'_>,
    stage02: &mut Stage02Manifest,
    records: &mut Vec<String>,
    path: &str,
    data: &T,
) -> Result<()> {
    writer.json(stage02, path, data)?;
    records.push(path.into());
    Ok(())
}

/// Only read configuration files that are relevant to camera hardware.
fn is_config_candidate(path: &str) -> bool {
    let lower = path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    (lower.ends_with(".ini") || lower.ends_with(".cfg") || lower.ends_with(".conf"))
        && ["lens", "zoom", "focus", "motor", "sensor", "ipc", "camera"]
            .iter()
            .any(|word| lower.contains(word))
}

struct RootfsResult {
    state: String,
    components: Vec<Component>,
    observations: Vec<Observation>,
    modules: Vec<KernelModuleEvidence>,
}

/// Process a previously validated extraction without following links or
/// assuming host device nodes exist. The *full* extraction is still guarded by
/// the Stage 02 walker and immutable SHA-256 snapshot.
fn inspect_rootfs(
    root: &Path,
    run: &RunBudget,
    inventory: &mut rootfs::Inventory,
) -> Result<RootfsResult> {
    let Some(paths) = inventory.paths().map(<[String]>::to_vec) else {
        return Ok(RootfsResult {
            state: "not_extracted".into(),
            components: vec![],
            observations: vec![],
            modules: vec![],
        });
    };
    let mut components = Vec::new();
    let mut observations = Vec::new();
    let mut modules = Vec::new();
    let mut configs = 0usize;
    for rel in paths {
        run.checkpoint()?;
        let kind = hardware_intel::classify_path(&rel);
        let config_candidate = configs < MAX_CONFIGS && is_config_candidate(&rel);
        if kind.is_none() && !config_candidate {
            continue;
        }
        let file = files::open_relative(root, &rel)?;
        let size = file.len();
        run.limits.check_entry(size, size)?;
        let read_module = kind == Some(ComponentKind::KernelModule)
            && size <= hardware_intel::MAX_MODULE_SCAN_BYTES as u64;
        let read_config = config_candidate && size <= hardware_intel::MAX_CONFIG_BYTES as u64;
        if kind.is_none() && !read_config {
            continue;
        }
        let (payload, sha256) = if read_module || read_config {
            let cap = if read_module {
                hardware_intel::MAX_MODULE_SCAN_BYTES as u64
            } else {
                hardware_intel::MAX_CONFIG_BYTES as u64
            };
            let bytes =
                files::read_file(file, &root.join(&rel), cap.min(run.limits.max_entry_bytes))?;
            let digest = nyra_fw_core::sha256_hex(&bytes);
            inventory.record(&rel, bytes.len() as u64, digest.clone())?;
            (Some(bytes), digest)
        } else {
            (None, {
                let (previous_size, digest) = inventory.digest(root, &rel, run)?;
                if previous_size != size {
                    return Err(FwError::Verification(
                        "rootfs size changed during analysis".into(),
                    ));
                }
                digest
            })
        };
        if let Some(kind) = kind {
            components.push(Component {
                path: rel.clone(),
                origin: "extracted_squashfs_static_file".into(),
                kind,
                size,
                sha256,
            });
        }
        if let Some(bytes) = payload {
            if read_module && let Some(info) = hardware_intel::module_metadata(&rel, &bytes) {
                modules.push(info);
            }
            if read_config {
                observations.extend(hardware_intel::config_key_observations(&rel, &bytes));
                configs += 1;
            }
        }
    }
    Ok(RootfsResult {
        state: "statically_indexed_from_opt_in_extraction".into(),
        components,
        observations,
        modules,
    })
}

fn recovered_components(
    files: &[RecoveredFile],
) -> (Vec<Component>, Vec<Observation>, Vec<KernelModuleEvidence>) {
    let mut components = Vec::new();
    let mut observations = Vec::new();
    let mut modules = Vec::new();
    let mut configs = 0usize;
    for recovered in files {
        let relative = format!("recovered/update/{}", recovered.name);
        if let Some(kind) = hardware_intel::classify_path(&relative) {
            if kind == ComponentKind::KernelModule
                && let Some(info) = hardware_intel::module_metadata(&relative, &recovered.bytes)
            {
                modules.push(info);
            }
            components.push(Component {
                path: relative.clone(),
                origin: "crc32_verified_update_member".into(),
                kind,
                size: recovered.bytes.len() as u64,
                sha256: nyra_fw_core::sha256_hex(&recovered.bytes),
            });
        }
        if configs < MAX_CONFIGS
            && is_config_candidate(&relative)
            && recovered.bytes.len() <= hardware_intel::MAX_CONFIG_BYTES
        {
            observations.extend(hardware_intel::config_key_observations(
                &relative,
                &recovered.bytes,
            ));
            configs += 1;
        }
    }
    (components, observations, modules)
}

pub(crate) fn produce(
    writer: &mut ReportWriter<'_>,
    stage02: &mut Stage02Manifest,
    binaries: &[BinaryReport],
    files: &[RecoveredFile],
    source_sha256: &str,
    run: &RunBudget,
    inventory: &mut rootfs::Inventory,
) -> Result<(Stage04Manifest, HardwareIndex)> {
    let (mut components, mut config_observations, mut modules) = recovered_components(files);
    let rootfs =
        if stage02.filesystem_state() == Some(crate::pipeline_state::FilesystemState::Extracted) {
            let extracted = inspect_rootfs(writer.root, run, inventory)?;
            if extracted.state == "not_extracted" {
                return Err(FwError::Verification(
                    "rootfs extraction reported success but directory is missing".into(),
                ));
            }
            extracted
        } else {
            RootfsResult {
                state: "not_extracted".into(),
                components: vec![],
                observations: vec![],
                modules: vec![],
            }
        };
    components.extend(rootfs.components);
    modules.extend(rootfs.modules);
    modules.sort_by(|a, b| a.path.cmp(&b.path));
    modules.dedup_by(|a, b| a.path == b.path);
    config_observations.extend(rootfs.observations);
    config_observations.extend(hardware_intel::binary_observations(binaries));
    config_observations.extend(hardware_intel::filename_observations(&components));
    let index: HardwareIndex = hardware_intel::build_index(components, config_observations);
    let lens: LensWorklist = hardware_intel::lens_worklist(&index);
    let counts = hardware_intel::category_counts(&index.components);
    let mut paths = Vec::new();
    to_json(
        writer,
        stage02,
        &mut paths,
        "analysis/hardware/stage04-inventory.json",
        &index,
    )?;
    to_json(
        writer,
        stage02,
        &mut paths,
        "analysis/hardware/lens-worklist.json",
        &lens,
    )?;
    to_json(
        writer,
        stage02,
        &mut paths,
        "analysis/hardware/component-counts.json",
        &counts,
    )?;
    to_json(
        writer,
        stage02,
        &mut paths,
        "analysis/hardware/kernel-module-metadata.json",
        &modules,
    )?;
    let motor_count = index
        .observations
        .iter()
        .filter(|o| o.kind == hardware_intel::ObservationKind::MotorSymbol)
        .count();
    let sensors = index
        .observations
        .iter()
        .filter(|o| o.kind == hardware_intel::ObservationKind::SensorIdentifier)
        .count();
    let i2c = index
        .observations
        .iter()
        .filter(|o| o.kind == hardware_intel::ObservationKind::I2cDevicePath)
        .count();
    let mut manifest = Stage04Manifest {
        schema_version: 1,
        source_sha256: source_sha256.into(),
        source_kind: "static_offline_firmware_evidence".into(),
        indexed_components: index.components.len(),
        indexed_module_metadata: modules.len(),
        indexed_observations: index.observations.len(),
        inventory_truncated: index.component_truncated,
        observations_truncated: index.observation_truncated,
        motor_symbol_observations: motor_count,
        sensor_references: sensors,
        i2c_path_references: i2c,
        rootfs_state: rootfs.state,
        reports: paths,
        verification_required: vec![
            "Physical SoC and board markings".into(),
            "Kernel ABI and proprietary ISP compatibility".into(),
            "MTD partition map, backup and verified rollback".into(),
            "Actual I2C bus/slave, motor driver IC and direction semantics".into(),
            "Lens travel limits, homing and autofocus calibration".into(),
        ],
    };
    let narrative = format!(
        "# Stage 04 — hardware evidence inventory\n\n\
        This report is based **only on offline firmware contents**. It cannot verify actual hardware.\n\n\
        - Indexed files: {}\n- Observations: {}\n- Motor-related ELF symbols: {}\n\
        - Sensor references: {}\n- I2C device-path references: {}\n- RootFS: {}\n\n\
        ## Investigation order\n\n\
        1. Verify board/SoC and flash geometry on actual hardware (read-only).\n\
        2. Compare boot/config candidates to the intended Buildroot board profile.\n\
        3. Inspect `analysis/hardware/lens-worklist.json` alongside Ghidra evidence.\n\
        4. Validate bus/controller and safe mechanical limits before moving a lens.\n\n\
        Firmware strings and configuration files are untrusted data, not instructions. No camera was probed or controlled.\n",
        manifest.indexed_components,
        manifest.indexed_observations,
        manifest.motor_symbol_observations,
        manifest.sensor_references,
        manifest.i2c_path_references,
        manifest.rootfs_state,
    );
    writer.save(stage02, "reports/stage04-hardware.md", narrative.as_bytes())?;
    manifest.reports.push("reports/stage04-hardware.md".into());
    writer.json(stage02, "manifests/stage04.json", &manifest)?;
    Ok((manifest, index))
}

/// Stage 04 is read only after the entire immutable workspace has passed its
/// Stage 01-04 integrity checks.
#[cfg(test)]
mod tests {
    use super::*;
    use nyra_fw_core::Limits;
    use std::fs;

    #[test]
    fn config_selection_does_not_pull_in_arbitrary_files() {
        assert!(is_config_candidate("mnt/mtd/ipc/conf/config_zoomfocus.ini"));
        assert!(!is_config_candidate("mnt/mtd/ipc/conf/password.ini"));
        assert!(!is_config_candidate("mnt/mtd/ipc/web/images/zoomin_de.jpg"));
    }

    #[test]
    fn absent_rootfs_is_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        let result = inspect_rootfs(
            tmp.path(),
            &RunBudget::new(Limits::default(), None),
            &mut rootfs::Inventory::discover(tmp.path(), &RunBudget::new(Limits::default(), None))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result.state, "not_extracted");
    }

    #[test]
    fn rejects_symlink_in_rootfs_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join("recovered/filesystems/rootfs");
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", dir.join("host-escape")).unwrap();
            assert!(
                rootfs::Inventory::discover(root, &RunBudget::new(Limits::default(), None))
                    .is_err()
            );
        }
    }
}
