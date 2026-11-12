//! Physical source coverage. Decoded coordinates never enter this map.
use nyra_fw_core::{FirmwareManifest, FwError, Result, Verification};
use nyra_fw_formats::candidates::{CandidateKind, CandidateReport, Status};
use serde::Serialize;
use std::collections::BTreeMap;

pub(crate) const PATH: &str = "analysis/workspace/byte-map.json";
const FILL_BLOCK: usize = 4096;

#[derive(Serialize)]
pub(crate) struct ByteMap<'a> {
    schema_version: u32,
    source_sha256: &'a str,
    input_bytes: u64,
    scan_budget_exhausted: Option<bool>,
    claims: Vec<Claim<'a>>,
    regions: Vec<Region>,
}

#[derive(Serialize)]
struct Claim<'a> {
    start: u64,
    end: u64,
    #[serde(flatten)]
    evidence: Evidence<'a>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Evidence<'a> {
    Artifact {
        path: &'a str,
        verification: Verification,
    },
    Candidate {
        id: u32,
        kind: CandidateKind,
        status: Status,
    },
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RegionKind {
    Unmapped,
    ZeroFill,
    ErasedByteFill,
    Claimed,
    MultipleClaims,
}

#[derive(Serialize)]
struct Region {
    start: u64,
    end: u64,
    kind: RegionKind,
    artifact_claims: i64,
    candidate_claims: i64,
}

pub(crate) fn derive<'a>(
    firmware: &'a FirmwareManifest,
    raw: &[u8],
    candidates: Option<&CandidateReport>,
) -> Result<ByteMap<'a>> {
    if firmware.source.size != raw.len() as u64 {
        return Err(FwError::Verification(
            "byte map source length mismatch".into(),
        ));
    }
    let mut claims = Vec::new();
    let mut events = BTreeMap::from([(0, [0i64; 2]), (raw.len() as u64, [0; 2])]);
    let mut add = |start: u64, length: u64, evidence: Evidence<'a>| -> Result<()> {
        let range = nyra_fw_core::source::ByteSource::new(
            raw,
            nyra_fw_core::source::Original {
                sha256: &firmware.source.sha256,
            },
        )
        .range(start, length)
        .ok_or_else(|| FwError::Verification("byte map claim outside source".into()))?;
        let end = range.start() + range.length();
        if start != end {
            let index = usize::from(matches!(evidence, Evidence::Candidate { .. }));
            events.entry(start).or_default()[index] += 1;
            events.entry(end).or_default()[index] -= 1;
            claims.push(Claim {
                start,
                end,
                evidence,
            });
        }
        Ok(())
    };
    for artifact in &firmware.artifacts {
        add(
            artifact.source_start,
            artifact.source_length,
            Evidence::Artifact {
                path: &artifact.path,
                verification: artifact.verification,
            },
        )?;
    }
    if let Some(report) = candidates {
        for candidate in &report.candidates {
            if candidate.container.is_none()
                && candidate.status.is_validated()
                && let Some(extent) = candidate.extent
            {
                add(
                    candidate.offset,
                    extent,
                    Evidence::Candidate {
                        id: candidate.id,
                        kind: candidate.kind,
                        status: candidate.status,
                    },
                )?;
            }
        }
    }
    let mut regions = Vec::<Region>::new();
    let mut start = 0;
    let mut active = [0, 0];
    for (end, delta) in events {
        if start < end {
            let [artifact_claims, candidate_claims] = active;
            if artifact_claims + candidate_claims == 0 {
                add_gap(&mut regions, start, &raw[start as usize..end as usize]);
            } else {
                let kind = if artifact_claims + candidate_claims > 1 {
                    RegionKind::MultipleClaims
                } else {
                    RegionKind::Claimed
                };
                regions.push(Region {
                    start,
                    end,
                    kind,
                    artifact_claims,
                    candidate_claims,
                });
            }
        }
        start = end;
        active[0] += delta[0];
        active[1] += delta[1];
    }
    Ok(ByteMap {
        schema_version: 1,
        source_sha256: &firmware.source.sha256,
        input_bytes: raw.len() as u64,
        scan_budget_exhausted: candidates.map(|report| report.budget_exhausted),
        claims,
        regions,
    })
}

fn add_gap(regions: &mut Vec<Region>, mut start: u64, bytes: &[u8]) {
    for block in bytes.chunks(FILL_BLOCK) {
        let end = start + block.len() as u64;
        let kind = match block.first() {
            Some(0) if block == [0; FILL_BLOCK] => RegionKind::ZeroFill,
            Some(255) if block == [255; FILL_BLOCK] => RegionKind::ErasedByteFill,
            _ => RegionKind::Unmapped,
        };
        if let Some(previous) = regions.last_mut()
            && previous.kind == kind
            && previous.end == start
        {
            previous.end = end;
        } else {
            regions.push(Region {
                start,
                end,
                kind,
                artifact_claims: 0,
                candidate_claims: 0,
            });
        }
        start = end;
    }
}
