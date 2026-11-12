//! Source-relative component relationships and root filesystem observations.
use crate::source_map;
use nyra_fw_core::{ArtifactKind, FirmwareManifest, Verification};
use nyra_fw_formats::{
    archive::RecoveredFile,
    candidates::{CandidateKind, CandidateReport, Status},
    squashfs,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const PATH: &str = "analysis/workspace/component-graph.json";

#[derive(Serialize)]
pub(crate) struct Graph<'a> {
    schema_version: u32,
    source_sha256: &'a str,
    source_path: String,
    candidates: Vec<Node<'a>>,
    artifacts: Vec<ArtifactNode<'a>>,
    root_filesystem_candidates: Vec<RootFilesystem<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "space", rename_all = "snake_case")]
enum Address {
    Original,
    DecodedGzip { container_candidate: u32 },
}

#[derive(Serialize)]
struct Node<'a> {
    id: u32,
    format: CandidateKind,
    address: Address,
    offset: u64,
    extent: Option<u64>,
    evidence: Status,
    nested_in: Option<u32>,
    conflicts_with: &'a [u32],
    carvable: bool,
}

#[derive(Serialize)]
struct ArtifactNode<'a> {
    path: &'a str,
    kind: ArtifactKind,
    evidence: Verification,
    source_offset: u64,
    source_length: u64,
    candidate: Option<u32>,
}

#[derive(Serialize)]
#[serde(tag = "reference", rename_all = "snake_case")]
enum RootFilesystem<'a> {
    Original,
    Artifact { path: &'a str },
    Candidate { id: u32 },
}

pub(crate) fn decoded_root_filesystems(
    members: &[RecoveredFile],
    gzip_payload: Option<&[u8]>,
) -> BTreeSet<String> {
    let mut paths: BTreeSet<_> = members
        .iter()
        .filter(|member| squashfs::inspect(&member.bytes).is_some())
        .map(|member| format!("recovered/update/{}", member.name))
        .collect();
    if gzip_payload.and_then(squashfs::inspect).is_some() {
        paths.insert(source_map::GZIP_PATH.to_owned());
    }
    paths
}

pub(crate) fn derive<'a>(
    manifest: &'a FirmwareManifest,
    raw: &[u8],
    report: Option<&'a CandidateReport>,
    decoded_root_filesystems: &BTreeSet<String>,
) -> Graph<'a> {
    let mut root_filesystems = Vec::new();
    if squashfs::inspect(raw).is_some() {
        root_filesystems.push(RootFilesystem::Original);
    }
    let mut paths = BTreeMap::new();
    let candidates: Vec<_> = report
        .into_iter()
        .flat_map(|report| &report.candidates)
        .filter(|candidate| candidate.status.is_validated())
        .map(|candidate| {
            if candidate.kind == CandidateKind::SquashFs {
                root_filesystems.push(RootFilesystem::Candidate { id: candidate.id });
            }
            if candidate.container.is_none() {
                paths.insert(source_map::candidate_path(candidate), candidate.id);
            }
            Node {
                id: candidate.id,
                format: candidate.kind,
                address: candidate
                    .container
                    .map_or(Address::Original, |container_candidate| {
                        Address::DecodedGzip {
                            container_candidate,
                        }
                    }),
                offset: candidate.offset,
                extent: candidate.extent,
                evidence: candidate.status,
                nested_in: candidate.nested_in,
                conflicts_with: &candidate.conflicts_with,
                carvable: candidate.carvable,
            }
        })
        .collect();
    let mut artifacts: Vec<_> = manifest.artifacts.iter().collect();
    artifacts.sort_unstable_by_key(|artifact| artifact.path.as_str());
    let artifacts = artifacts
        .into_iter()
        .map(|artifact| {
            let direct_squashfs = artifact.transformation.starts_with("raw-carve:")
                && nyra_fw_core::source::ByteSource::new(
                    raw,
                    nyra_fw_core::source::Original {
                        sha256: &manifest.source.sha256,
                    },
                )
                .range(artifact.source_start, artifact.source_length)
                .map(|range| range.bytes())
                .and_then(squashfs::inspect)
                .is_some();
            if direct_squashfs || decoded_root_filesystems.contains(&artifact.path) {
                root_filesystems.push(RootFilesystem::Artifact {
                    path: &artifact.path,
                });
            }
            ArtifactNode {
                path: &artifact.path,
                kind: artifact.kind,
                evidence: artifact.verification,
                source_offset: artifact.source_start,
                source_length: artifact.source_length,
                candidate: paths.get(&artifact.path).copied(),
            }
        })
        .collect();
    Graph {
        schema_version: 1,
        source_sha256: &manifest.source.sha256,
        source_path: format!("original/{}", manifest.source.filename),
        candidates,
        artifacts,
        root_filesystem_candidates: root_filesystems,
    }
}
