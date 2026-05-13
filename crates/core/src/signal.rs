//! Signal model. Providers attach these to a dependency; the policy engine
//! then maps signals to a `Decision`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::dependency::ResolvedDependency;

/// A single fact about a `(name, version)` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Signal {
    /// When this version was first published to its registry.
    PublishedAt { at: DateTime<Utc> },
    /// Lifecycle scripts declared in `package.json`.
    LifecycleScripts { scripts: Vec<String> },
    /// The provider could not produce signals for this dependency. Always
    /// recorded so policy can decide how to treat unknowns.
    Unavailable { provider: String, reason: String },
}

/// Aggregated signal output for a single dependency.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignalSet {
    pub signals: Vec<Signal>,
}

impl SignalSet {
    #[must_use]
    pub fn published_at(&self) -> Option<DateTime<Utc>> {
        self.signals.iter().find_map(|s| match s {
            Signal::PublishedAt { at } => Some(*at),
            _ => None,
        })
    }

    #[must_use]
    pub fn lifecycle_scripts(&self) -> Option<&[String]> {
        self.signals.iter().find_map(|s| match s {
            Signal::LifecycleScripts { scripts } => Some(scripts.as_slice()),
            _ => None,
        })
    }

    pub fn push(&mut self, signal: Signal) {
        self.signals.push(signal);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("network: {0}")]
    Network(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("unsupported ecosystem")]
    UnsupportedEcosystem,
}

/// Implementations live in `crates/signals/<id>/`.
#[async_trait::async_trait]
pub trait SignalProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports(&self, dep: &ResolvedDependency) -> bool;
    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError>;
}
