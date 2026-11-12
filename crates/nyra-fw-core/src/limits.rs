//! Hard bounds for hostile firmware inputs, in bytes unless noted otherwise.
use crate::{FwError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_input_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_total_output_bytes: u64,
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_extra_field_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_entry_bytes: 32 * 1024 * 1024,
            max_total_output_bytes: 256 * 1024 * 1024,
            max_entries: 20_000,
            max_path_bytes: 512,
            max_extra_field_bytes: 8192,
        }
    }
}

impl Limits {
    pub fn check_input(&self, count: u64) -> Result<()> {
        if count > self.max_input_bytes {
            return Err(FwError::Limit(format!(
                "input {count} exceeds {}",
                self.max_input_bytes
            )));
        }
        Ok(())
    }

    pub fn check_entry(&self, compressed: u64, plain: u64) -> Result<()> {
        if compressed > self.max_entry_bytes || plain > self.max_entry_bytes {
            return Err(FwError::Limit(format!(
                "entry compressed={compressed} plain={plain} exceeds {}",
                self.max_entry_bytes
            )));
        }
        Ok(())
    }

    pub fn check_total(&self, count: u64) -> Result<()> {
        if count > self.max_total_output_bytes {
            return Err(FwError::Limit(format!(
                "total decoded {count} exceeds {}",
                self.max_total_output_bytes
            )));
        }
        Ok(())
    }
}
