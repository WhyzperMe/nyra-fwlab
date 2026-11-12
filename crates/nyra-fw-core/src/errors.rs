//! Domain-specific, actionable failures; untrusted input must never panic.
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum FwError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported firmware: {0}")]
    Unsupported(String),
    #[error("invalid firmware: {0}")]
    Invalid(String),
    #[error("resource limit exceeded: {0}")]
    Limit(String),
    #[error("analysis sandbox exceeded its wall-clock budget")]
    ToolTimeout,
    #[error("recovery verification failed: {0}")]
    Verification(String),
    #[error("unsafe output path: {0}")]
    UnsafePath(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("output already exists: {0}")]
    AlreadyExists(PathBuf),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, FwError>;

pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> FwError {
    FwError::Io {
        path: path.into(),
        source,
    }
}
