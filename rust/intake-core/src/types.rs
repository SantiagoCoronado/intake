//! Core data structures for intake.
//!
//! Direct port of `intake_shield/types.py`.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// TrustLevel
// ---------------------------------------------------------------------------

/// Ordered trust levels. Higher value = more trusted.
///
/// Mirrors Python's `TrustLevel(IntEnum)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustLevel {
    Hostile = 0,
    Untrusted = 10,
    Trusted = 20,
    Owner = 30,
}

impl TrustLevel {
    pub fn value(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Hostile => "hostile",
            Self::Untrusted => "untrusted",
            Self::Trusted => "trusted",
            Self::Owner => "owner",
        }
    }

    fn from_value(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Hostile),
            10 => Some(Self::Untrusted),
            20 => Some(Self::Trusted),
            30 => Some(Self::Owner),
            _ => None,
        }
    }
}

impl PartialOrd for TrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Custom serde: deserializes from integer (0, 10, 20, 30) to match YAML policy files.
impl<'de> Deserialize<'de> for TrustLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = u64::deserialize(deserializer)?;
        Self::from_value(v).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "invalid trust level: {v}. Expected 0, 10, 20, or 30"
            ))
        })
    }
}

impl Serialize for TrustLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.value())
    }
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Known input source channels.
///
/// Mirrors Python's `Channel(str, Enum)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Channel {
    #[serde(rename = "owner_cli")]
    OwnerCli,
    #[serde(rename = "api_authorized")]
    ApiAuthorized,
    #[serde(rename = "external_email")]
    ExternalEmail,
    #[serde(rename = "external_discord")]
    ExternalDiscord,
    #[serde(rename = "external_webhook")]
    ExternalWebhook,
    #[serde(rename = "file_content")]
    FileContent,
    #[serde(rename = "tool_output")]
    ToolOutput,
    #[serde(rename = "system")]
    System,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnerCli => "owner_cli",
            Self::ApiAuthorized => "api_authorized",
            Self::ExternalEmail => "external_email",
            Self::ExternalDiscord => "external_discord",
            Self::ExternalWebhook => "external_webhook",
            Self::FileContent => "file_content",
            Self::ToolOutput => "tool_output",
            Self::System => "system",
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Matcher<T> — handles wildcard "*" in policy rules
// ---------------------------------------------------------------------------

/// A policy selector that is either a specific value or a wildcard `"*"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher<T> {
    Wildcard,
    Specific(T),
}

impl<T> Matcher<T>
where
    T: PartialEq,
{
    /// Returns `true` if this matcher matches `value` (wildcard matches everything).
    pub fn matches(&self, value: &T) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Specific(v) => v == value,
        }
    }
}

/// Custom deserializer: `"*"` → Wildcard, otherwise delegate to T's deserializer.
impl<'de, T> Deserialize<'de> for Matcher<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into an untyped Value first so we can check for "*".
        let value = serde_yaml::Value::deserialize(deserializer)?;
        if let serde_yaml::Value::String(ref s) = value {
            if s == "*" {
                return Ok(Matcher::Wildcard);
            }
        }
        T::deserialize(value)
            .map(Matcher::Specific)
            .map_err(serde::de::Error::custom)
    }
}

impl<T: Serialize> Serialize for Matcher<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Wildcard => serializer.serialize_str("*"),
            Self::Specific(v) => v.serialize(serializer),
        }
    }
}

impl<T> Default for Matcher<T> {
    fn default() -> Self {
        Self::Wildcard
    }
}

// ---------------------------------------------------------------------------
// PolicyRule
// ---------------------------------------------------------------------------

/// A single policy rule mapping (channel, trust) → permissions.
///
/// Mirrors Python's `PolicyRule(BaseModel)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    #[serde(default)]
    pub channel: Matcher<Channel>,
    #[serde(default)]
    pub trust: Matcher<TrustLevel>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub priority: i32,
}

// ---------------------------------------------------------------------------
// PolicyConfig
// ---------------------------------------------------------------------------

/// Top-level policy document.
///
/// Mirrors Python's `PolicyConfig(BaseModel)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_true")]
    pub default_deny: bool,
    pub rules: Vec<PolicyRule>,
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// TaggedInput
// ---------------------------------------------------------------------------

/// An input segment with immutable trust metadata.
///
/// Mirrors Python's `TaggedInput(BaseModel, frozen=True)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedInput {
    pub id: String,
    pub content: String,
    pub channel: Channel,
    pub trust: TrustLevel,
    #[serde(default)]
    pub source_description: String,
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TaggedInput {
    /// Create a new TaggedInput with an auto-generated ID and timestamp.
    pub fn new(content: impl Into<String>, channel: Channel, trust: TrustLevel) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..12].to_string(),
            content: content.into(),
            channel,
            trust,
            source_description: String::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_description = source.into();
        self
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }
}

// ---------------------------------------------------------------------------
// ToolCall
// ---------------------------------------------------------------------------

/// Represents an intended tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub originating_inputs: Vec<String>,
}

// ---------------------------------------------------------------------------
// EvalResult
// ---------------------------------------------------------------------------

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub allowed: bool,
    pub matched_rule: Option<PolicyRule>,
    pub reason: String,
}
