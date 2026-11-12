//! Static ELF indexing and the reports derived from it: dependencies, lens and
//! hardware observations.
use crate::{files, output::json, report_writer::ReportWriter, rootfs, stage02::Stage02Manifest};
use nyra_fw_analysis::{
    binary::{self, BinaryReport},
    dependencies, hardware, lens,
};
use nyra_fw_core::{FwError, Result, budget::RunBudget};
use nyra_fw_formats::{archive::RecoveredFile, magic};
use rayon::prelude::*;

/// ELF files indexed per workspace, recovered and extracted together.
const MAX_ELF_CANDIDATES: usize = 512;
const MAX_ELF_REPORT_BYTES: usize = 24 * 1024 * 1024;
const LENS_README_ENTRIES: usize = 100;

pub(crate) struct ElfIndex {
    pub(crate) binaries: Vec<BinaryReport>,
    pub(crate) errors: Vec<String>,
    /// ELF files recovered from the input itself, as opposed to an extracted filesystem.
    pub(crate) recovered_sources: Vec<String>,
}

fn too_many() -> FwError {
    FwError::Limit(format!(
        "too many ELF candidates (maximum {MAX_ELF_CANDIDATES})"
    ))
}

/// Parse every ELF among the recovered members, the standalone input and, when a
/// filesystem was extracted, its regular files. Parsing is parallel and bounded; the
/// result is sorted so it does not depend on scheduling.
pub(crate) fn index(
    root: &std::path::Path,
    run: &RunBudget,
    members: &[RecoveredFile],
    standalone: Option<(&str, &[u8])>,
    inventory: &mut rootfs::Inventory,
) -> Result<ElfIndex> {
    let candidates: Vec<_> = members
        .iter()
        .filter(|f| f.bytes.starts_with(magic::ELF))
        .map(|f| (f.name.as_str(), f.bytes.as_slice()))
        .chain(standalone)
        .collect();
    if candidates.len() > MAX_ELF_CANDIDATES {
        return Err(too_many());
    }
    let mut binaries: Vec<BinaryReport> = Vec::new();
    let mut errors = Vec::new();
    let mut report_bytes = 0usize;
    let mut add_report = |name: &str, output| -> Result<()> {
        match output {
            Ok(report) => {
                report_bytes += json(&report)?.len();
                if report_bytes > MAX_ELF_REPORT_BYTES {
                    return Err(FwError::Limit("aggregate ELF report exceeds 24 MiB".into()));
                }
                binaries.push(report);
            }
            Err(err) => errors.push(format!("{name}: {err}")),
        }
        Ok(())
    };
    run.batches(
        &candidates,
        |(_, bytes)| 16 * 1024 * 1024 + bytes.len() as u64,
        |batch| {
            let inspected: Vec<_> = batch
                .par_iter()
                .map(|(name, bytes)| binary::inspect(name, bytes))
                .collect();
            for ((name, _), output) in batch.iter().zip(inspected) {
                add_report(name, output)?;
            }
            Ok(())
        },
    )?;
    if inventory.paths().is_some() {
        let mut seen = candidates.len();
        for relative in inventory.paths().unwrap_or_default().to_vec() {
            run.checkpoint()?;
            let Some(bytes) =
                files::read_matching(root, &relative, magic::ELF, run.limits.max_entry_bytes)?
            else {
                continue;
            };
            seen += 1;
            if seen > MAX_ELF_CANDIDATES {
                return Err(too_many());
            }
            let report = binary::inspect(&relative, &bytes);
            if let Ok(report) = &report {
                inventory.record(&relative, bytes.len() as u64, report.sha256.clone())?;
            }
            add_report(&relative, report)?;
        }
    }
    binaries.sort_by(|a, b| a.source.cmp(&b.source));
    errors.sort();
    let recovered_sources = candidates
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    Ok(ElfIndex {
        binaries,
        errors,
        recovered_sources,
    })
}

/// A label safe to copy into generated prose. Symbol names come from the firmware
/// and must not carry backticks, newlines or other markup into an agent's context.
fn safe_label(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.' | '/' | ':'))
        .take(150)
        .collect()
}

/// Write the ELF index and every report derived from it, in a fixed order.
pub(crate) fn write_reports(
    writer: &mut ReportWriter<'_>,
    manifest: &mut Stage02Manifest,
    index: &ElfIndex,
) -> Result<()> {
    let binaries = &index.binaries;
    manifest.scanned_elfs = binaries.len();
    writer.json(manifest, "analysis/binaries/elf-index.json", binaries)?;
    writer.json(
        manifest,
        "analysis/binaries/parse-errors.json",
        &index.errors,
    )?;
    writer.json(
        manifest,
        "analysis/binaries/dependencies.json",
        &dependencies::summarize(binaries),
    )?;
    let lens_data = lens::discover(binaries);
    writer.json(manifest, "analysis/lens/function-index.json", &lens_data)?;
    writer.json(
        manifest,
        "analysis/hardware/observed-strings.json",
        &hardware::references(binaries),
    )?;
    let mut readme = String::from(
        "# Lens and motor evidence\n\nNo live hardware operation was performed. Symbols and strings are observations, not proven motion semantics.\n\n",
    );
    for function in lens_data.functions.iter().take(LENS_README_ENTRIES) {
        readme.push_str(&format!(
            "- `{}` at `0x{:x}` in `{}`\n",
            safe_label(&function.symbol),
            function.address,
            safe_label(&function.source)
        ));
    }
    if lens_data.functions.len() > LENS_README_ENTRIES {
        readme.push_str("\nMore entries in `function-index.json`.\n");
    }
    writer.save(manifest, "analysis/lens/README.md", readme.as_bytes())
}
