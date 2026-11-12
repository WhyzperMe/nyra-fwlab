//! Versioned dispatch, evidence inventory, and verified reuse metadata.
use crate::pipeline_state::RecoveryState;
use crate::{files, report_writer::ReportWriter, stage02::Stage02Manifest};
use nyra_fw_core::{FirmwareManifest, FwError, Result};
use nyra_fw_formats::{
    archive::RecoveredFile,
    input::{self, InputKind},
    squashfs, uimage,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PATH: &str = "manifests/stage06.json";

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Run {
    schema_version: u32,
    source_sha256: String,
    detected_format: String,
    pub(crate) recovery_state: RecoveryState,
    cache_key: Option<String>,
    full_flash_verified: bool,
}

#[derive(Serialize)]
struct Component<'a> {
    path: &'a str,
    format: InputKind,
    evidence: &'static str,
    squashfs: Option<squashfs::SquashFsMetadata>,
    uimage: Option<uimage::Image>,
}

fn component<'a>(
    path: &'a str,
    bytes: &[u8],
    analysis: &Stage02Manifest,
    elf_sources: &std::collections::BTreeSet<&str>,
) -> Component<'a> {
    let format = input::identify(bytes);
    let squashfs = (format == InputKind::SquashFs)
        .then(|| squashfs::inspect(bytes))
        .flatten();
    let uimage = (format == InputKind::UImage)
        .then(|| uimage::inspect(bytes))
        .flatten();
    let source = path.strip_prefix("recovered/update/").unwrap_or(path);
    let evidence = match format {
        InputKind::SquashFs if squashfs.is_some() => "validated_superblock",
        InputKind::UImage if uimage.is_some() => "validated_header_and_payload_crc32",
        InputKind::ElfCandidate if elf_sources.contains(source) => "elf_parsed",
        InputKind::Pihc | InputKind::Zip if source.starts_with("original/") => {
            if format == InputKind::Zip
                && analysis.central_directory_state
                    == nyra_fw_formats::central::DirectoryState::Valid
            {
                "validated_local_and_central_metadata"
            } else if format == InputKind::Pihc
                && nyra_fw_formats::pihc::PihcHeader::parse(bytes).is_ok()
            {
                "validated_header_bounds"
            } else {
                "magic_only"
            }
        }
        InputKind::Unknown => "unrecognized",
        _ => "magic_only",
    };
    Component {
        path,
        format,
        evidence,
        squashfs,
        uimage,
    }
}

pub(crate) struct SourceBytes<'a> {
    pub original: (&'a str, &'a [u8]),
    pub gzip_payload: Option<&'a [u8]>,
}

pub(crate) fn produce(
    writer: &mut ReportWriter<'_>,
    analysis: &mut Stage02Manifest,
    firmware: &FirmwareManifest,
    input: SourceBytes<'_>,
    members: &[RecoveredFile],
    elf_sources: std::collections::BTreeSet<&str>,
    cache_key: Option<&str>,
) -> Result<()> {
    let original = input.original;
    let mut source = component(original.0, original.1, analysis, &elf_sources);
    if input.gzip_payload.is_some() {
        source.evidence = "validated_crc32_and_isize";
    } else if source.format == InputKind::Tar && !firmware.is_unverified() {
        source.evidence = "validated_tar_headers_and_member_bounds";
    }
    let incomplete_elf =
        source.format == InputKind::ElfCandidate && source.evidence != "elf_parsed";
    let carves = firmware
        .artifacts
        .iter()
        .filter(|a| a.kind != nyra_fw_core::ArtifactKind::ArchiveMember)
        .filter_map(|a| {
            if a.transformation == "gzip:single-member" {
                return Some(component(
                    &a.path,
                    input.gzip_payload?,
                    analysis,
                    &elf_sources,
                ));
            }
            let start = usize::try_from(a.source_start).ok()?;
            let length = usize::try_from(a.source_length).ok()?;
            let bytes = original.1.get(start..start.checked_add(length)?)?;
            Some(component(&a.path, bytes, analysis, &elf_sources))
        });
    let records: Vec<_> = firmware
        .artifacts
        .iter()
        .filter(|a| a.kind == nyra_fw_core::ArtifactKind::ArchiveMember)
        .zip(members)
        .map(|(a, member)| component(&a.path, &member.bytes, analysis, &elf_sources))
        .chain(carves)
        .chain(std::iter::once(source))
        .collect();
    let run = Run {
        schema_version: 1,
        source_sha256: firmware.source.sha256.clone(),
        detected_format: firmware.detected_format.clone(),
        recovery_state: if firmware.recovery_complete_for_recognized_entries()
            && firmware.summary.unsupported_entries == 0
        {
            RecoveryState::RecognizedMembersVerified
        } else if firmware.summary.failed_entries != 0
            || firmware.summary.unsupported_entries != 0
            || firmware.summary.duplicate_names != 0
            || firmware.is_unverified()
            || incomplete_elf
        {
            RecoveryState::Partial
        } else {
            RecoveryState::PreservedAndInspected
        },
        cache_key: cache_key.map(str::to_owned),
        full_flash_verified: false,
    };
    writer.json(analysis, "analysis/workspace/components.json", &records)?;
    writer.json(analysis, PATH, &run)
}

pub(crate) fn read(
    root: &Path,
    firmware: &FirmwareManifest,
    inventory: &crate::integrity::Inventory,
) -> Result<Option<Run>> {
    if !inventory.contains(PATH) {
        if firmware.producer == concat!("nyra-fwlab/", env!("CARGO_PKG_VERSION")) {
            return Err(FwError::Verification(
                "Stage 06 run metadata missing".into(),
            ));
        }
        return Ok(None);
    }
    let run: Run = inventory.read_json(root, PATH, files::MANIFEST_BYTES)?;
    if run.schema_version != 1
        || run.source_sha256 != firmware.source.sha256
        || run.detected_format != firmware.detected_format
        || run.full_flash_verified
    {
        return Err(FwError::Verification(
            "Stage 06 run metadata inconsistent".into(),
        ));
    }
    Ok(Some(run))
}

pub(crate) fn verify_cache(
    root: &Path,
    firmware: &FirmwareManifest,
    inventory: &crate::integrity::Inventory,
    key: &str,
) -> Result<()> {
    if read(root, firmware, inventory)?
        .and_then(|run| run.cache_key)
        .as_deref()
        != Some(key)
    {
        return Err(FwError::Verification(
            "existing workspace does not match requested input and recovery options".into(),
        ));
    }
    Ok(())
}
