//! Format-neutral records emitted after archive member verification.
use crate::{central::DirectoryAudit, zip::LocalEntry};
use nyra_fw_core::{FwError, Result};
use serde::Serialize;
use std::collections::HashMap;

/// Reserve portable paths, including implicit directories, before publishing.
#[derive(Default)]
pub(crate) struct PortablePaths(HashMap<String, (String, bool)>);

impl PortablePaths {
    pub(crate) fn reserve(
        &mut self,
        path: &str,
        directory: bool,
        max_entries: usize,
    ) -> Result<bool> {
        let prefixes: Vec<_> = path
            .match_indices('/')
            .map(|(i, _)| (&path[..i], false))
            .chain(std::iter::once((path, !directory)))
            .map(|(prefix, file)| (prefix.to_ascii_lowercase(), prefix, file))
            .collect();
        if prefixes.iter().any(|(key, prefix, file)| {
            self.0
                .get(key)
                .is_some_and(|(prior, prior_file)| prior != prefix || *file || *prior_file)
        }) {
            return Ok(false);
        }
        for (key, prefix, file) in prefixes {
            self.0
                .entry(key)
                .or_insert_with(|| (prefix.to_owned(), file));
        }
        if self.0.len() > max_entries.saturating_mul(2) {
            return Err(FwError::Limit("too many archive path components".into()));
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMethod {
    Original,
    Decrypted,
}

#[derive(Debug, Clone)]
pub struct RecoveredFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub method: RecoveryMethod,
    /// Absolute offsets refer to the original input.
    pub header_offset: u64,
    pub data_offset: u64,
    pub compressed_size: u64,
}

impl RecoveredFile {
    pub(crate) fn from_entry(
        entry: &LocalEntry,
        bytes: Vec<u8>,
        method: RecoveryMethod,
        base: usize,
    ) -> Result<Self> {
        let absolute = |offset| {
            base.checked_add(offset)
                .map(|offset| offset as u64)
                .ok_or_else(|| FwError::Invalid("absolute archive offset overflow".into()))
        };
        Ok(Self {
            name: entry.name.clone(),
            bytes,
            method,
            header_offset: absolute(entry.header_offset)?,
            data_offset: absolute(entry.data_offset)?,
            compressed_size: entry.compressed_size as u64,
        })
    }
}

#[derive(Debug)]
pub struct ArchiveReport {
    pub directory: DirectoryAudit,
    pub issues: Vec<ArchiveIssue>,
}

#[derive(Debug, Serialize)]
pub struct ArchiveIssue {
    pub header_offset: u64,
    pub reason: Exclusion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exclusion {
    InvalidHeader,
    UnsupportedName,
    UnsupportedEncoding,
    EntryLimit,
    PathCollision,
    ContentVerificationFailed,
}
