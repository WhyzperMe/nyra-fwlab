//! Runtime states; public manifest strings remain the versioned wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemState {
    NotPresent,
    SuperblockValidated,
    Extracted,
    Failed,
}

impl FilesystemState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotPresent => "not_present",
            Self::SuperblockValidated => "superblock_validated_only",
            Self::Extracted => "extracted_without_live_symlinks",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "not_present" => Some(Self::NotPresent),
            "superblock_validated_only" => Some(Self::SuperblockValidated),
            "extracted_without_live_symlinks" => Some(Self::Extracted),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryState {
    RecognizedMembersVerified,
    Partial,
    PreservedAndInspected,
}

impl RecoveryState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RecognizedMembersVerified => "recognized_members_verified",
            Self::Partial => "partial",
            Self::PreservedAndInspected => "preserved_and_inspected",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_labels_remain_stable_and_unknown_states_fail() {
        for state in [
            FilesystemState::NotPresent,
            FilesystemState::SuperblockValidated,
            FilesystemState::Extracted,
            FilesystemState::Failed,
        ] {
            assert_eq!(FilesystemState::parse(state.label()), Some(state));
        }
        assert_eq!(FilesystemState::parse("complete"), None);
        for state in [
            RecoveryState::RecognizedMembersVerified,
            RecoveryState::Partial,
            RecoveryState::PreservedAndInspected,
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
            assert_eq!(
                serde_json::from_str::<RecoveryState>(&serde_json::to_string(&state).unwrap())
                    .unwrap(),
                state
            );
        }
        assert!(serde_json::from_str::<RecoveryState>("\"complete\"").is_err());
    }
}
