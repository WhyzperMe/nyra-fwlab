//! Read-only format inspection and bounded candidate presentation.
use crate::output::out;
use nyra_fw_core::{FwError, Limits, Result, budget::RunBudget};
use nyra_fw_formats::{
    candidates, central,
    input::{self, InputKind},
    pihc,
    zip::scan_local_entries,
};
use std::{path::PathBuf, time::Instant};

pub(crate) fn run(
    firmware: PathBuf,
    all_candidates: bool,
    json: bool,
    limits: Limits,
    run_deadline: Instant,
) -> Result<()> {
    let bytes = nyra_fw_workspace::read_input(&firmware, limits.max_input_bytes)?;
    let kind = input::identify(&bytes);
    // A failed structure check is a finding, not a reason to stop: the scan
    // reports which class of check failed and still searches for candidates.
    let budget = RunBudget::new(limits.clone(), Some(run_deadline));
    let mut archive = None;
    let state = if matches!(kind, InputKind::Zip | InputKind::Tar) {
        input::inspect_archive(kind, &bytes, &budget).map(|index| {
            let state = index.structural_state();
            archive = Some(index);
            state
        })
    } else {
        input::structural_state(kind, &bytes, &limits)
    };
    let (structural, rejection) = match state {
        Ok(state) => (state, None),
        Err(error) => (
            "rejected",
            Some(match error {
                FwError::Limit(_) | FwError::ToolTimeout => "resource_limit",
                FwError::Unsupported(_) => "unsupported",
                FwError::Io { .. } | FwError::Json(_) => "read_error",
                _ => "structure_check_failed",
            }),
        ),
    };
    let sha256 = nyra_fw_core::sha256_hex(&bytes);
    let mut report = serde_json::json!({
        "schema_version": 1, "format": kind.label(), "structural_state": structural,
        "rejection_class": rejection,
        "bytes": bytes.len(), "sha256": sha256, "files_recovered": false,
        "complete_firmware_established": false
    });
    if let Some(index) = archive
        && json
    {
        report["archive"] = serde_json::to_value(index.finding(&sha256))?;
    }
    if kind == InputKind::Pihc && rejection.is_none() {
        let header = pihc::PihcHeader::parse(&bytes)?;
        let (entries, stats) = scan_local_entries(header.archive(&bytes), &limits)?;
        let directory = central::audit(header.archive(&bytes), &entries, &limits);
        report["archive_offset"] = header.archive_offset.into();
        report["pre_archive_squashfs_magic"] = header.pre_archive_is_squashfs.into();
        report["eligible_entries"] = stats.eligible.into();
        report["unsupported_entries"] = stats.unsupported.into();
        report["central_directory"] = serde_json::to_value(&directory)?;
        if !json {
            out!(
                "PIHC archive offset 0x{:x} | ZIP signatures {} | eligible {} | unsupported {}",
                header.archive_offset,
                stats.signatures,
                stats.eligible,
                stats.unsupported
            );
            out!(
                "Central directory {:?}, matched {}",
                directory.state,
                directory.matched_local_entries
            );
        }
    }
    let candidates = if all_candidates
        || kind == InputKind::ElfCandidate
        || rejection.is_some()
        || matches!(structural, "magic_only" | "unrecognized")
    {
        Some(candidates::scan(&bytes, &sha256, &budget)?)
    } else {
        None
    };
    report["candidates"] = serde_json::to_value(&candidates)?;
    if json {
        out!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        out!(
            "{} | {} | {} bytes | SHA-256 {}",
            kind.label(),
            structural,
            bytes.len(),
            sha256
        );
        if let Some(candidates) = &candidates {
            out!(
                "Candidate scan: {:?} | {} signature hit(s) | {} validation attempt(s){}",
                candidates.outcome,
                candidates.signature_hits,
                candidates.validation_attempts,
                if candidates.budget_exhausted {
                    " | scan budget reached, findings incomplete"
                } else {
                    ""
                }
            );
            // Top-level findings first. Structures contained in a validated
            // parent are summarized; the full list is in the JSON output.
            let (top, nested): (Vec<_>, Vec<_>) = candidates
                .candidates
                .iter()
                .partition(|c| c.nested_in.is_none() && c.container.is_none());
            for candidate in top.iter().take(32) {
                out!("  {}", candidates::summary_line(candidate));
            }
            if top.len() > 32 {
                out!(
                    "  ... {} more top-level candidates in --json output",
                    top.len() - 32
                );
            }
            if !nested.is_empty() || candidates.hits_explained_by_structure != 0 {
                out!(
                    "  {} nested candidate(s) and {} hit(s) explained by a validated structure omitted; see --json",
                    nested.len(),
                    candidates.hits_explained_by_structure
                );
            }
            for step in &candidates.next_steps {
                out!("  next: {}", step.description);
            }
        }
        out!("Scan only. Full flash coverage remains unverified.");
    }
    Ok(())
}
