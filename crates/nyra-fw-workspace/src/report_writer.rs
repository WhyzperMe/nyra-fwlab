//! Bounded, exclusive writes of analysis reports, each indexed by SHA-256.
use crate::{files, output::write_new, stage02::Stage02Manifest};
use nyra_fw_core::{FwError, Result, budget::RunBudget};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A report file with the digest recorded in `manifests/analysis.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

pub(crate) struct ReportWriter<'a> {
    pub(crate) root: &'a Path,
    run: &'a RunBudget,
    remaining: u64,
}

impl<'a> ReportWriter<'a> {
    /// Aggregate budget for all analysis reports of one workspace.
    const TOTAL_BYTES: u64 = 256 * 1024 * 1024;

    pub(crate) fn new(root: &'a Path, run: &'a RunBudget) -> Self {
        Self {
            root,
            run,
            remaining: Self::TOTAL_BYTES,
        }
    }

    pub(crate) fn save(
        &mut self,
        manifest: &mut Stage02Manifest,
        path: &str,
        bytes: &[u8],
    ) -> Result<()> {
        self.run.checkpoint()?;
        let size = bytes.len() as u64;
        if size > files::REPORT_BYTES || size > self.remaining {
            return Err(FwError::Limit(format!(
                "analysis report budget exceeded: {path}"
            )));
        }
        write_new(self.root, path, bytes)?;
        self.remaining -= size;
        manifest.analysis_files.push(AnalysisFile {
            path: path.into(),
            size,
            sha256: nyra_fw_core::sha256_hex(bytes),
        });
        Ok(())
    }

    pub(crate) fn json<T: Serialize + ?Sized>(
        &mut self,
        manifest: &mut Stage02Manifest,
        path: &str,
        value: &T,
    ) -> Result<()> {
        struct BoundedJson {
            bytes: Vec<u8>,
            cap: usize,
        }
        impl std::io::Write for BoundedJson {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.cap - self.bytes.len() {
                    return Err(std::io::Error::other("report size limit"));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut buffer = BoundedJson {
            bytes: Vec::new(),
            cap: self.remaining.min(files::REPORT_BYTES) as usize,
        };
        serde_json::to_writer_pretty(&mut buffer, value).map_err(|err| {
            if err.is_io() {
                FwError::Limit(format!("analysis report budget exceeded: {path}"))
            } else {
                err.into()
            }
        })?;
        self.save(manifest, path, &buffer.bytes)
    }
}
