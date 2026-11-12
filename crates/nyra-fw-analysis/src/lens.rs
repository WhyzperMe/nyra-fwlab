//! Conservative lens/motor discovery based on ELF symbols and immutable strings.
//! Hardware addresses are deliberately *not* inferred from names or string hits.
use crate::binary::BinaryReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensFunction {
    pub source: String,
    pub symbol: String,
    pub address: u64,
    pub size: u64,
    /// False for a symbol with no address in this binary, such as an imported function.
    #[serde(default = "defined_by_default")]
    pub defined: bool,
    pub evidence: String,
}

fn defined_by_default() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensEvidence {
    pub source: String,
    pub value: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensReport {
    pub functions: Vec<LensFunction>,
    pub strings: Vec<LensEvidence>,
    pub motor_controller_model: Option<String>,
    pub i2c_slave_address: Option<u16>,
    pub note: String,
}

pub fn discover(reports: &[BinaryReport]) -> LensReport {
    let mut functions = Vec::new();
    let mut strings = Vec::new();
    for binary in reports {
        for s in &binary.symbols {
            let name = s.name.to_ascii_lowercase();
            if [
                "hi_af_",
                "hi_ptz_motor_af",
                "zoom",
                "focus",
                "lens",
                "motor",
            ]
            .iter()
            .any(|key| name.contains(key))
            {
                functions.push(LensFunction {
                    source: binary.source.clone(),
                    symbol: s.name.clone(),
                    address: s.address,
                    size: s.size,
                    defined: s.address != 0,
                    evidence: "ELF symbol table".into(),
                });
            }
        }
        for value in &binary.strings {
            let lower = value.to_ascii_lowercase();
            if ["/dev/i2c", "zoom", "focus", "lens", "motor", "autofocus"]
                .iter()
                .any(|key| lower.contains(key))
            {
                strings.push(LensEvidence {
                    source: binary.source.clone(),
                    value: value.clone(),
                    evidence: "embedded printable bytes".into(),
                });
            }
        }
    }
    LensReport {
        functions, strings,
        motor_controller_model: None,
        i2c_slave_address: None,
        note: "Symbol/string presence does not prove active hardware code paths, bus slave addresses, directions, or actuator limits. Check disassembly and physical board before any motor motion.".into(),
    }
}
