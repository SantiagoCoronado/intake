//! Error types for intake-core.
//!
//! Mirrors `intake_shield/exceptions.py`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntakeError {
    #[error("policy load error: {0}")]
    PolicyLoad(String),

    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    #[error("action blocked: {0}")]
    ActionBlocked(String),

    #[error("provenance error: {0}")]
    Provenance(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}
