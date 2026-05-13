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
    /// The npm publisher (`_npmUser.name`) for the resolved version
    /// differs from the publisher of the immediately-prior released
    /// version. A common precursor to account-takeover supply-chain
    /// attacks (cf. event-stream, ua-parser-js). `previous_version` is
    /// the highest released version strictly less than the resolved
    /// version under semver ordering.
    PublisherChange {
        previous_version: String,
        previous: String,
        current: String,
    },
    /// The registry has marked this version as deprecated. The optional
    /// `message` is the human-readable string the maintainer (or the
    /// registry) attached when the deprecation was recorded. Captures
    /// post-publish trust changes — a common path for malicious
    /// versions to be pulled out of circulation while existing
    /// lockfiles continue to pin them.
    DeprecatedVersion { message: Option<String> },
    /// A lifecycle script body matched a high-risk pattern from
    /// `script_scan`. One signal per (script, pattern); `excerpt` is a
    /// short, UTF-8-safe slice of the script body around the match,
    /// suitable for embedding in audit logs without bloating them.
    SuspiciousScript {
        script: String,
        pattern: String,
        excerpt: String,
    },
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

    /// Returns the publisher-change signal if one was recorded.
    /// Tuple is `(previous_version, previous_publisher, current_publisher)`.
    #[must_use]
    pub fn publisher_change(&self) -> Option<(&str, &str, &str)> {
        self.signals.iter().find_map(|s| match s {
            Signal::PublisherChange {
                previous_version,
                previous,
                current,
            } => Some((
                previous_version.as_str(),
                previous.as_str(),
                current.as_str(),
            )),
            _ => None,
        })
    }

    /// Returns the deprecation signal if one was recorded. Inner option
    /// is the maintainer-supplied message (registries often record an
    /// empty string for "no message"; that becomes `Some("")`).
    #[must_use]
    pub fn deprecated(&self) -> Option<Option<&str>> {
        self.signals.iter().find_map(|s| match s {
            Signal::DeprecatedVersion { message } => Some(message.as_deref()),
            _ => None,
        })
    }

    /// Iterator over all suspicious-script findings recorded for this
    /// dependency. Tuple is `(script, pattern, excerpt)`.
    pub fn suspicious_scripts(&self) -> impl Iterator<Item = (&str, &str, &str)> + '_ {
        self.signals.iter().filter_map(|s| match s {
            Signal::SuspiciousScript {
                script,
                pattern,
                excerpt,
            } => Some((script.as_str(), pattern.as_str(), excerpt.as_str())),
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
