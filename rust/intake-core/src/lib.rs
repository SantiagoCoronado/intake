//! intake-core: Trust boundary enforcement for AI agents.
//!
//! This crate provides the core policy engine and context annotation system
//! from the [intake](https://github.com/santiagocoronado/intake) project,
//! ported from the Python `intake_shield` package.
//!
//! # Overview
//!
//! - **PolicyEngine** — Loads YAML policy files and evaluates whether tool calls
//!   are permitted given a `(tool_name, channel, trust_level)` tuple.
//! - **ContextWindowBuilder** — Constructs LLM message arrays with structural
//!   trust annotations (`<intake>` XML tags) and a trust protocol preamble.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::path::Path;
//! use intake_core::{PolicyEngine, Channel, TrustLevel};
//!
//! let engine = PolicyEngine::from_yaml(Path::new("policy.yaml")).unwrap();
//! let result = engine.evaluate("shell_exec", Channel::ExternalEmail, TrustLevel::Untrusted);
//! assert!(!result.allowed);
//! ```

#![deny(unsafe_code)]

pub mod context;
pub mod error;
pub mod policy;
pub mod types;

// Re-export primary API at crate root.
pub use context::{ContextWindowBuilder, Message, TRUST_PROTOCOL_PREAMBLE};
pub use error::IntakeError;
pub use policy::PolicyEngine;
pub use types::{
    Channel, EvalResult, Matcher, PolicyConfig, PolicyRule, TaggedInput, ToolCall, TrustLevel,
};
