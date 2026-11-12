//! Evidence-preserving index of DT_NEEDED names against recovered ELF objects.
//! This is NOT a simulation of the target dynamic loader or its search paths.
use crate::binary::BinaryReport;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    UniqueCandidate,
    AmbiguousCandidates,
    NotPresentInRecoveredSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeededLibrary {
    pub requester: String,
    pub library: String,
    pub candidates: Vec<String>,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub schema_version: u32,
    pub objects: usize,
    pub references: usize,
    pub unresolved: usize,
    pub ambiguous: usize,
    pub edges: Vec<NeededLibrary>,
    pub caveat: String,
}

/// Match by DT_SONAME (when present) or basename; distinguish absent from ambiguous.
/// ELF loader resolution additionally needs filesystem mounts, RPATH, ld.so and ABI.
pub fn build(reports: &[BinaryReport]) -> DependencyGraph {
    const MAX_EDGES: usize = 20_000;
    const MAX_CANDIDATES: usize = 32;
    let mut remaining_candidate_bytes = 4 * 1024 * 1024;
    let mut truncated = false;
    let mut index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for report in reports {
        if let Some(base) = Path::new(&report.source)
            .file_name()
            .and_then(|s| s.to_str())
        {
            index
                .entry(base.to_owned())
                .or_default()
                .insert(report.source.clone());
        }
        if let Some(name) = &report.soname {
            index
                .entry(name.clone())
                .or_default()
                .insert(report.source.clone());
        }
    }
    let mut edges = Vec::new();
    'reports: for report in reports {
        for requested in &report.libraries {
            if edges.len() >= MAX_EDGES {
                truncated = true;
                break 'reports;
            }
            let matches = index.get(requested);
            let count = matches.map_or(0, BTreeSet::len);
            let resolution = match count {
                0 => Resolution::NotPresentInRecoveredSet,
                1 => Resolution::UniqueCandidate,
                _ => Resolution::AmbiguousCandidates,
            };
            let candidates: Vec<_> = matches
                .into_iter()
                .flatten()
                .take(MAX_CANDIDATES)
                .take_while(|name| {
                    if name.len() > remaining_candidate_bytes {
                        return false;
                    }
                    remaining_candidate_bytes -= name.len();
                    true
                })
                .cloned()
                .collect();
            truncated |= candidates.len() < count;
            edges.push(NeededLibrary {
                requester: report.source.clone(),
                library: requested.clone(),
                candidates,
                resolution,
            });
        }
    }
    edges.sort_by(|a, b| {
        a.requester
            .cmp(&b.requester)
            .then(a.library.cmp(&b.library))
    });
    let unresolved = edges
        .iter()
        .filter(|x| x.resolution == Resolution::NotPresentInRecoveredSet)
        .count();
    let ambiguous = edges
        .iter()
        .filter(|x| x.resolution == Resolution::AmbiguousCandidates)
        .count();
    DependencyGraph {
        schema_version: 1, objects: reports.len(), references: edges.len(), unresolved, ambiguous, edges,
        caveat: if truncated {
            "Dependency edges or candidate lists reached analysis limits. Counts cover indexed edges. Candidate resolution uses filenames and DT_SONAME only."
        } else {
            "Candidates are inferred from filenames / DT_SONAME only. An absent candidate does not prove a broken runtime: the update or extraction may be incomplete."
        }.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryReport, ElfSecurity};
    fn report(path: &str, soname: Option<&str>, libs: &[&str]) -> BinaryReport {
        BinaryReport {
            source: path.into(),
            sha256: "0".repeat(64),
            file_type: "shared_object".into(),
            machine: 40,
            word_size: 32,
            little_endian: true,
            entry_point: 0,
            interpreter: None,
            soname: soname.map(str::to_owned),
            libraries: libs.iter().map(|s| (*s).into()).collect(),
            rpaths: vec![],
            runpaths: vec![],
            symbols: vec![],
            strings: vec![],
            string_hits: vec![],
            truncated: false,
            security: ElfSecurity::default(),
        }
    }
    #[test]
    fn exact_match_ambiguous_and_missing_are_distinct() {
        let g = build(&[
            report("app", None, &["liba.so", "libb.so", "missing.so"]),
            report("usr/lib/liba.so", None, &[]),
            report("other/libb.so", None, &[]),
            report("usr/lib/libb.so", None, &[]),
        ]);
        assert_eq!(g.unresolved, 1);
        assert_eq!(g.ambiguous, 1);
        assert_eq!(g.edges[0].resolution, Resolution::UniqueCandidate);
        assert_eq!(g.edges[1].candidates.len(), 2);
    }
    #[test]
    fn soname_alias_resolves() {
        let g = build(&[
            report("app", None, &["libalpha.so.1"]),
            report("lib/libalpha.so.1.2", Some("libalpha.so.1"), &[]),
        ]);
        assert_eq!(g.unresolved, 0);
    }
}
