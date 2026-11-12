//! Validation, nesting and conflict analysis of signature hits.
use super::{
    BOUNDS, Candidate, CandidateKind, CandidateReport, Check, Entropy, LIMITATION, NextStep,
    Outcome, Reason, SCHEMA_VERSION, Status, StepCode,
    entropy::entropy,
    headers::{elf_extent, fdt_extent, ubi_header, xz_header},
    hits::{Hits, collect_hits},
};
use crate::{gzip, input, pihc::PihcHeader, squashfs, uimage};
use nyra_fw_core::{FwError, Limits, Result, budget::RunBudget};

struct Verdict {
    checks: Vec<Check>,
    status: Status,
    reason: Option<Reason>,
    extent: Option<u64>,
    payload: Option<Vec<u8>>,
    /// Local header offsets of a validated ZIP, in the coordinates of the scanned region.
    members: Vec<u64>,
}

impl Verdict {
    fn new() -> Self {
        Self {
            checks: Vec::new(),
            status: Status::SignatureOnly,
            reason: None,
            extent: None,
            payload: None,
            members: Vec::new(),
        }
    }

    /// Record a check; returns whether validation may continue.
    fn check(&mut self, name: &'static str, passed: bool) -> bool {
        self.checks.push(Check { name, passed });
        if !passed {
            self.status = Status::Rejected;
        }
        passed
    }

    fn with_check(mut self, name: &'static str) -> Self {
        self.checks.push(Check { name, passed: true });
        self
    }

    fn fail(mut self, name: &'static str) -> Self {
        self.check(name, false);
        self
    }

    fn validated(mut self, status: Status, extent: Option<u64>) -> Self {
        self.status = status;
        self.extent = extent;
        self
    }

    fn skipped(mut self, reason: Reason) -> Self {
        self.status = Status::SignatureOnly;
        self.reason = Some(reason);
        self
    }
}

struct Scan<'a> {
    run: &'a RunBudget,
    limits: &'a Limits,
    candidates: Vec<Candidate>,
    attempts: usize,
    decoded: u64,
    validation_bytes: u64,
    zip_ends_not_examined: u64,
    exhausted: bool,
    explained_hits: u64,
}

pub fn scan(raw: &[u8], source_sha256: &str, run: &RunBudget) -> Result<CandidateReport> {
    run.limits.check_input(raw.len() as u64)?;
    let limits = run.limits.clone();
    let mut scan = Scan {
        run,
        limits: &limits,
        candidates: Vec::new(),
        attempts: 0,
        decoded: 0,
        validation_bytes: 0,
        zip_ends_not_examined: 0,
        exhausted: false,
        explained_hits: 0,
    };
    let mut signature_hits = 0;
    let mut hits_not_examined = 0;
    // The source is scanned in place. Decoded gzip payloads are queued as owned
    // regions, breadth first, so candidate ids are deterministic.
    let mut queue: Vec<Region> = Vec::new();
    let hits = collect_hits(raw, run)?;
    signature_hits += hits.total;
    hits_not_examined += hits.not_examined;
    scan.region(raw, None, 0, &hits, &mut queue)?;
    let mut next = 0;
    while next < queue.len() {
        let (container, depth, bytes) = std::mem::take(&mut queue[next]);
        next += 1;
        let hits = collect_hits(&bytes, run)?;
        signature_hits += hits.total;
        hits_not_examined += hits.not_examined;
        scan.region(&bytes, container, depth, &hits, &mut queue)?;
    }
    scan.exhausted |= hits_not_examined != 0 || scan.zip_ends_not_examined != 0;
    scan.relate();
    let (outcome, next_steps, entropy) = {
        let entropy = entropy(raw, run)?;
        let outcome = scan.outcome(signature_hits);
        let steps = scan.steps(outcome, &entropy);
        (outcome, steps, entropy)
    };
    Ok(CandidateReport {
        schema_version: SCHEMA_VERSION,
        source_sha256: source_sha256.to_owned(),
        input_bytes: raw.len() as u64,
        bounds: BOUNDS,
        outcome,
        signature_hits,
        hits_not_examined,
        hits_explained_by_structure: scan.explained_hits,
        validation_attempts: scan.attempts as u64,
        decoded_bytes: scan.decoded,
        validation_bytes: scan.validation_bytes,
        zip_ends_not_examined: scan.zip_ends_not_examined,
        budget_exhausted: scan.exhausted,
        entropy,
        candidates: scan.candidates,
        next_steps,
        limitation: LIMITATION,
    })
}

type Region = (Option<u32>, u8, Vec<u8>);

/// A validated structure that accounts for some signatures inside its extent.
struct Explaining {
    start: u64,
    end: u64,
    kind: CandidateKind,
    /// For a ZIP, the offsets of its local member headers.
    members: Vec<u64>,
}

impl Explaining {
    /// Whether this structure accounts for a signature of kind `inner` at `offset`. A ZIP
    /// explains only its own member headers: an archive stored inside a member starts at
    /// another offset and needs its own check. A SquashFS explains the block streams inside
    /// it. Everything else inside a payload still needs its own structure check.
    fn explains(&self, inner: CandidateKind, offset: u64) -> bool {
        if offset <= self.start || offset >= self.end {
            return false;
        }
        match self.kind {
            CandidateKind::Zip => {
                inner == CandidateKind::Zip && self.members.binary_search(&offset).is_ok()
            }
            CandidateKind::SquashFs => matches!(
                inner,
                CandidateKind::Xz | CandidateKind::Bzip2 | CandidateKind::Zstd
            ),
            _ => false,
        }
    }
}

impl Scan<'_> {
    fn charge_validation(&mut self, bytes: u64) -> bool {
        if bytes > BOUNDS.max_validation_bytes - self.validation_bytes {
            self.exhausted = true;
            return false;
        }
        self.validation_bytes += bytes;
        true
    }

    fn region(
        &mut self,
        bytes: &[u8],
        container: Option<u32>,
        depth: u8,
        hits: &Hits,
        queue: &mut Vec<Region>,
    ) -> Result<()> {
        self.zip_ends_not_examined += hits.zip_ends_dropped;
        // Extents of validated structures in this region, to recognize hits that the
        // structure itself explains: member headers of a ZIP and the block streams of a
        // SquashFS. They are counted, not listed, and spend no validation attempt.
        let mut explaining: Vec<Explaining> = Vec::new();
        for &(offset, kind) in &hits.found {
            self.run.checkpoint()?;
            if self.candidates.len() >= BOUNDS.max_candidates {
                self.exhausted = true;
                break;
            }
            if explaining.iter().any(|outer| outer.explains(kind, offset)) {
                self.explained_hits += 1;
                continue;
            }
            let id = self.candidates.len() as u32;
            let verdict = if !kind.has_parser() {
                Verdict::new().skipped(Reason::NoParserInThisBuild)
            } else if self.attempts >= BOUNDS.max_validation_attempts {
                self.exhausted = true;
                Verdict::new().skipped(Reason::AttemptBudgetExhausted)
            } else {
                self.validate(kind, bytes, offset as usize, hits)
            };
            if matches!(kind, CandidateKind::Zip | CandidateKind::SquashFs)
                && verdict.status.is_validated()
                && let Some(extent) = verdict.extent
            {
                explaining.push(Explaining {
                    start: offset,
                    end: offset.saturating_add(extent),
                    kind,
                    members: verdict.members.clone(),
                });
            }
            if let Some(payload) = verdict.payload.filter(|payload| !payload.is_empty()) {
                if depth < BOUNDS.max_depth {
                    queue.push((Some(id), depth + 1, payload));
                } else {
                    self.exhausted = true;
                }
            }
            self.candidates.push(Candidate {
                id,
                kind,
                container,
                depth,
                offset,
                extent: verdict.extent,
                status: verdict.status,
                reason: verdict.reason,
                checks: verdict.checks,
                nested_in: None,
                conflicts_with: Vec::new(),
                carvable: false,
            });
        }
        Ok(())
    }

    fn validate(
        &mut self,
        kind: CandidateKind,
        bytes: &[u8],
        offset: usize,
        hits: &Hits,
    ) -> Verdict {
        let tail = &bytes[offset..];
        match kind {
            CandidateKind::Zip => return self.validate_zip(bytes, offset, hits),
            CandidateKind::Gzip => return self.validate_gzip(tail),
            _ => self.attempts += 1,
        }
        let verdict = Verdict::new();
        let pass = |verdict: Verdict, status, extent, name| {
            verdict.validated(status, extent).with_check(name)
        };
        match kind {
            CandidateKind::Pihc => match PihcHeader::parse(tail) {
                Ok(_) => pass(
                    verdict,
                    Status::StructureValidated,
                    None,
                    "pihc_header_and_archive_offset",
                ),
                Err(_) => verdict.fail("pihc_header_and_archive_offset"),
            },
            CandidateKind::SquashFs => match squashfs::validate(tail) {
                Ok(meta) => pass(
                    verdict,
                    Status::StructureValidated,
                    Some(meta.bytes_used),
                    "squashfs_superblock",
                ),
                Err(name) => verdict.fail(name),
            },
            CandidateKind::UImage => match uimage::validate_with_budget(tail, |size| {
                self.charge_validation(size)
            }) {
                Ok(image) => pass(
                    verdict,
                    Status::PayloadVerified,
                    Some(uimage::HEADER_SIZE as u64 + u64::from(image.payload_bytes)),
                    "uimage_header_and_payload_crc32",
                ),
                Err("uimage_payload_budget") => verdict.skipped(Reason::ValidationBudgetExhausted),
                Err(name) => verdict.fail(name),
            },
            CandidateKind::Elf => match elf_extent(tail) {
                Ok(extent) => pass(
                    verdict,
                    Status::StructureValidated,
                    Some(extent),
                    "elf_header_tables_and_extent",
                ),
                Err(name) => verdict.fail(name),
            },
            CandidateKind::Fdt => match fdt_extent(tail, |size| self.charge_validation(size)) {
                Ok(extent) => pass(
                    verdict,
                    Status::StructureValidated,
                    Some(extent),
                    "fdt_header_blocks_and_tokens",
                ),
                Err("fdt_validation_budget") => verdict.skipped(Reason::ValidationBudgetExhausted),
                Err(name) => verdict.fail(name),
            },
            CandidateKind::Ubi => match ubi_header(tail) {
                Ok(()) => pass(
                    verdict,
                    Status::StructureValidated,
                    None,
                    "ubi_erase_counter_header_crc32",
                ),
                Err(name) => verdict.fail(name),
            },
            CandidateKind::Xz => match xz_header(tail) {
                Ok(()) => pass(
                    verdict,
                    Status::StructureValidated,
                    None,
                    "xz_stream_header_crc32",
                ),
                Err(name) => verdict.fail(name),
            },
            _ => verdict.skipped(Reason::NoParserInThisBuild),
        }
    }

    fn validate_gzip(&mut self, tail: &[u8]) -> Verdict {
        self.attempts += 1;
        let mut verdict = Verdict::new();
        let remaining = BOUNDS.max_decoded_bytes - self.decoded;
        if remaining == 0 {
            self.exhausted = true;
            return verdict.skipped(Reason::DecodeBudgetExhausted);
        }
        let input_cap = usize::try_from(BOUNDS.max_validation_bytes - self.validation_bytes)
            .unwrap_or(usize::MAX)
            .min(tail.len());
        if input_cap < 10 && input_cap < tail.len() {
            self.exhausted = true;
            return verdict.skipped(Reason::ValidationBudgetExhausted);
        }
        // Reserve room for the decoder's one-byte overflow probe.
        let cap = (remaining - 1).min(self.limits.max_entry_bytes);
        let mut work = gzip::DecodeWork::default();
        let decoded = gzip::decode_prefix_metered(&tail[..input_cap], cap, &mut work);
        self.validation_bytes += work.input;
        self.decoded += work.output;
        match decoded {
            Ok((payload, consumed)) => {
                verdict.check("gzip_header_deflate_crc32_isize", true);
                verdict.status = Status::PayloadVerified;
                verdict.extent = Some(consumed as u64);
                verdict.payload = Some(payload);
                verdict
            }
            Err(FwError::Limit(_)) => {
                self.exhausted = true;
                verdict.skipped(Reason::DecodeBudgetExhausted)
            }
            Err(_) if input_cap < tail.len() && work.input == input_cap as u64 => {
                self.exhausted = true;
                verdict.skipped(Reason::ValidationBudgetExhausted)
            }
            Err(_) => verdict.fail("gzip_header_deflate_crc32_isize"),
        }
    }

    fn validate_zip(&mut self, bytes: &[u8], offset: usize, hits: &Hits) -> Verdict {
        let mut verdict = Verdict::new();
        let ends = hits.zip_ends.get(&offset).map_or(&[][..], Vec::as_slice);
        let mut needs_zip64 = false;
        for &stop in ends {
            if self.attempts >= BOUNDS.max_validation_attempts {
                self.exhausted = true;
                return verdict.skipped(Reason::AttemptBudgetExhausted);
            }
            if !self.charge_validation((stop - offset) as u64) {
                return verdict.skipped(Reason::ValidationBudgetExhausted);
            }
            self.attempts += 1;
            // The structure is judged without the extraction policy: a member that uses a
            // method this build cannot decode does not make the archive's records invalid.
            match input::zip_structure(&bytes[offset..stop], self.limits) {
                Ok(structure) => {
                    verdict.members = structure
                        .member_offsets
                        .iter()
                        .map(|&member| (offset + member) as u64)
                        .collect();
                    verdict.check("zip_central_and_local_records", true);
                    return verdict
                        .validated(Status::StructureValidated, Some((stop - offset) as u64));
                }
                Err(input::ZipStructureError::Zip64) => needs_zip64 = true,
                Err(input::ZipStructureError::Invalid) => {}
            }
        }
        if hits.zip_ends_dropped != 0 {
            return verdict.skipped(Reason::ZipEndBudgetExhausted);
        }
        verdict.fail(if needs_zip64 {
            "zip_classic_32bit_records"
        } else {
            "zip_central_and_local_records"
        })
    }

    /// Containment and overlap between validated candidates of one coordinate
    /// space. A candidate without a proven extent can be contained but never
    /// contains or overlaps another one.
    fn relate(&mut self) {
        let validated: Vec<usize> = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.status.is_validated())
            .map(|(index, _)| index)
            .collect();
        let mut nested: Vec<Option<(u32, u64)>> = vec![None; self.candidates.len()];
        let mut conflicts: Vec<Vec<u32>> = vec![Vec::new(); self.candidates.len()];
        for (position, &i) in validated.iter().enumerate() {
            for &j in &validated[position + 1..] {
                let (a, b) = (&self.candidates[i], &self.candidates[j]);
                if a.container != b.container {
                    continue;
                }
                if a.offset == b.offset {
                    // Two different structures claim the same first byte.
                    conflicts[i].push(b.id);
                    conflicts[j].push(a.id);
                    continue;
                }
                let (low, high, low_index, high_index) = if a.offset < b.offset {
                    (a, b, i, j)
                } else {
                    (b, a, j, i)
                };
                let Some(low_end) = low.extent.map(|extent| low.offset.saturating_add(extent))
                else {
                    continue;
                };
                if high.offset >= low_end {
                    continue;
                }
                let contained = high
                    .extent
                    .is_none_or(|extent| high.offset.saturating_add(extent) <= low_end);
                if contained {
                    let size = low.extent.unwrap_or(u64::MAX);
                    if nested[high_index].is_none_or(|(_, best)| size < best) {
                        nested[high_index] = Some((low.id, size));
                    }
                } else {
                    conflicts[low_index].push(high.id);
                    conflicts[high_index].push(low.id);
                }
            }
        }
        for &index in &validated {
            let candidate = &mut self.candidates[index];
            candidate.nested_in = nested[index].map(|(id, _)| id);
            candidate.conflicts_with = std::mem::take(&mut conflicts[index]);
            candidate.conflicts_with.sort_unstable();
            candidate.carvable = candidate.container.is_none()
                && candidate.extent.is_some()
                && candidate.nested_in.is_none()
                && candidate.conflicts_with.is_empty();
        }
    }

    fn outcome(&self, signature_hits: u64) -> Outcome {
        let structures = self
            .candidates
            .iter()
            .filter(|c| c.container.is_none() && c.status.is_validated() && c.nested_in.is_none())
            .count();
        if self.candidates.iter().any(|c| !c.conflicts_with.is_empty()) {
            Outcome::Ambiguous
        } else if structures > 1 {
            Outcome::MultipleDisjointStructures
        } else if structures == 1 {
            Outcome::SingleStructure
        } else if signature_hits == 0 {
            Outcome::NoSignatures
        } else {
            Outcome::SignaturesWithoutValidation
        }
    }

    fn steps(&self, outcome: Outcome, entropy: &Entropy) -> Vec<NextStep> {
        let ids = |filter: &dyn Fn(&Candidate) -> bool| -> Vec<u32> {
            self.candidates
                .iter()
                .filter(|c| filter(c))
                .map(|c| c.id)
                .collect()
        };
        let mut steps = Vec::new();
        let mut push = |code, candidates: Vec<u32>, description| {
            if !candidates.is_empty() || matches!(code, StepCode::NoKnownSignature) {
                steps.push(NextStep {
                    code,
                    candidates,
                    description,
                });
            }
        };
        push(
            StepCode::AnalyzeCarvedCandidate,
            ids(&|c| c.carvable),
            "Analyze each carved candidate as a standalone input with the matching reader. The carve is byte-identical to the listed source range.",
        );
        push(
            StepCode::ResolveOverlappingCandidates,
            ids(&|c| !c.conflicts_with.is_empty()),
            "These validated candidates overlap and none was selected. Compare their structure with an independent reference before choosing one.",
        );
        push(
            StepCode::StructureWithoutDecoder,
            ids(&|c| {
                c.container.is_none()
                    && c.status == Status::StructureValidated
                    && c.extent.is_none()
                    && c.nested_in.is_none()
            }),
            "A header check passed but its extent is unknown, so nothing was carved. A trusted external tool in an isolated environment can decode it. This build does not.",
        );
        push(
            StepCode::SignatureWithoutDecoder,
            ids(&|c| c.reason == Some(Reason::NoParserInThisBuild)),
            "The signature matched, but this build has no parser for the format. The offset is a lead, not evidence of a valid structure.",
        );
        if self.exhausted {
            steps.push(NextStep {
                code: StepCode::BudgetExhausted,
                candidates: ids(&|c| {
                    matches!(
                        c.reason,
                        Some(Reason::AttemptBudgetExhausted | Reason::DecodeBudgetExhausted
                            | Reason::ValidationBudgetExhausted | Reason::ZipEndBudgetExhausted)
                    )
                }),
                description: "A scan budget was reached. Findings are incomplete. Candidates marked with a budget reason were not validated.",
            });
        }
        if matches!(
            outcome,
            Outcome::NoSignatures | Outcome::SignaturesWithoutValidation
        ) {
            let blocks = entropy.blocks.max(1);
            if entropy.high_entropy_blocks * 10 >= blocks * 8 {
                steps.push(NextStep {
                    code: StepCode::HighEntropyNoSignature,
                    candidates: Vec::new(),
                    description: "Most blocks are near-uniform, which is consistent with compression, encryption or random data. The bytes alone do not tell these apart. A key, decoder or vendor documentation is needed.",
                });
            } else if entropy.uniform_fill_blocks * 2 >= blocks {
                steps.push(NextStep {
                    code: StepCode::MostlyPaddingNoSignature,
                    candidates: Vec::new(),
                    description: "At least half of the blocks hold one repeated byte value. The input is mostly padding or erased flash, and no structure was found in the rest.",
                });
            } else {
                steps.push(NextStep {
                    code: StepCode::NoKnownSignature,
                    candidates: Vec::new(),
                    description: "No supported structure was found within the scan bounds. The diagnosis ends here. The source bytes are preserved for another tool.",
                });
            }
        }
        steps
    }
}
