//! Bounded, explainable lens-centric neighborhood of Ghidra static call references.
//! Ghidra exports names, not unique function IDs; colliding names remain ambiguous.
use crate::{
    callgraph::{CallEdge, StaticCallGraph},
    symbols::GhidraFunctions,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensCallNeighborhood {
    pub schema_version: u32,
    pub source: String,
    pub root_symbols: Vec<String>,
    pub depth_limit: usize,
    pub edges: Vec<CallEdge>,
    pub name_collisions: Vec<String>,
    pub note: String,
}

fn relevant(name: &str) -> bool {
    let value = name.to_ascii_lowercase();
    [
        "zoom",
        "focus",
        "lens",
        "motor",
        "hi_af_",
        "i2c",
        "autofocus",
    ]
    .iter()
    .any(|term| value.contains(term))
}

pub fn build(
    source: &str,
    funcs: &GhidraFunctions,
    graph: &StaticCallGraph,
) -> LensCallNeighborhood {
    const DEPTH: usize = 2;
    const MAX_EDGES: usize = 2_000;
    let mut names = std::collections::BTreeMap::<String, usize>::new();
    for f in &funcs.functions {
        *names.entry(f.name.clone()).or_default() += 1;
    }
    let roots: BTreeSet<String> = names.keys().filter(|k| relevant(k)).cloned().collect();
    let mut visited = roots.clone();
    let mut frontier: VecDeque<(String, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    let mut adjacency: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, edge) in graph.edges.iter().enumerate() {
        adjacency.entry(edge.caller.as_str()).or_default().push(idx);
        if edge.caller != edge.callee {
            adjacency.entry(edge.callee.as_str()).or_default().push(idx);
        }
    }
    let mut selected = BTreeSet::<(String, String, String)>::new();
    while let Some((current, depth)) = frontier.pop_front() {
        if depth >= DEPTH || selected.len() >= MAX_EDGES {
            continue;
        }
        if let Some(indices) = adjacency.get(current.as_str()) {
            for &idx in indices {
                if selected.len() >= MAX_EDGES {
                    break;
                }
                let edge = &graph.edges[idx];
                selected.insert((edge.caller.clone(), edge.callee.clone(), edge.site.clone()));
                let next = if edge.caller == current {
                    &edge.callee
                } else {
                    &edge.caller
                };
                if visited.insert(next.clone()) {
                    frontier.push_back((next.clone(), depth + 1));
                }
            }
        }
    }
    LensCallNeighborhood {
        schema_version: 1, source: source.into(), root_symbols: roots.into_iter().collect(), depth_limit: DEPTH,
        edges: selected.into_iter().map(|(caller, callee, site)| CallEdge { caller, callee, site }).collect(),
        name_collisions: names.into_iter().filter_map(|(name, n)| (n > 1).then_some(name)).collect(),
        note: "Edges represent Ghidra's static calls to function entry points, in a two-hop name-based neighborhood. They do not prove actual control flow, indirect calls, or physical hardware behavior.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::GhidraFunction;
    #[test]
    fn two_hops_and_non_lens_edges() {
        let names = ["HI_AF_I2cRunZoom", "dispatch", "i2c_write", "far", "other"];
        let funcs = GhidraFunctions {
            schema_version: 1,
            exported: names.len(),
            functions: names
                .iter()
                .map(|name| GhidraFunction {
                    name: (*name).into(),
                    entry: "1000".into(),
                    size: 1,
                    external: false,
                })
                .collect(),
        };
        let edges = [
            ("HI_AF_I2cRunZoom", "dispatch"),
            ("dispatch", "other"),
            ("other", "far"),
        ];
        let graph = StaticCallGraph {
            schema_version: 1,
            kind: "static_entry_references".into(),
            exported: edges.len(),
            edges: edges
                .iter()
                .map(|(a, b)| CallEdge {
                    caller: (*a).into(),
                    callee: (*b).into(),
                    site: "1002".into(),
                })
                .collect(),
        };
        let result = build("ipc_server", &funcs, &graph);
        assert!(result.edges.iter().any(|e| e.callee == "dispatch"));
        assert!(result.edges.iter().any(|e| e.callee == "other"));
        assert!(!result.edges.iter().any(|e| e.callee == "far"));
    }
}
