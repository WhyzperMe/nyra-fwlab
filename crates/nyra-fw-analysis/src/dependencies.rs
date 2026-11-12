//! Static DT_NEEDED dependency inventory, not an executable linker validation.
use crate::binary::BinaryReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub binary: String,
    pub needs: Vec<String>,
}

pub fn summarize(reports: &[BinaryReport]) -> Vec<Dependency> {
    reports
        .iter()
        .map(|b| Dependency {
            binary: b.source.clone(),
            needs: b.libraries.clone(),
        })
        .collect()
}
