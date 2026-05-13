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
    /// New executable / lifecycle entry-points appeared between the
    /// immediately-prior released version and the resolved version
    /// (`bin` map keys and lifecycle-script names). Captures the
    /// post-takeover “new postinstall in a patch release” pattern
    /// without requiring tarball download. `previous_version` is the
    /// highest released version strictly less than the resolved
    /// version under semver.
    VersionSurfaceChange {
        previous_version: String,
        added_bins: Vec<String>,
        added_scripts: Vec<String>,
    },
    /// The `latest` dist-tag points to a version that is strictly
    /// older than the highest non-prerelease published version.
    /// This is the “latest moved backwards” pattern — a classic
    /// way to silently ship a malicious patch-only version while
    /// hiding it from `npm outdated`. `latest_version` is what
    /// `dist-tags.latest` resolves to; `highest_published` is the
    /// real maximum.
    DistTagAnomaly {
        latest_version: String,
        highest_published: String,
    },
    /// The package name is close-but-not-equal to a popular
    /// package on the curated typosquat list, or uses confusable
    /// Unicode codepoints that fold to a popular name. `style` is
    /// `"typo"` or `"homoglyph"` (named `style` rather than `kind`
    /// to avoid colliding with serde's enum-tag field); `target`
    /// is the popular name it resembles. See
    /// [`crate::name_similarity`].
    NameSquat { style: String, target: String },
    /// The npm account that published this version was itself
    /// created very recently — a strong signal of an
    /// account-takeover or a fresh-throwaway publisher. Carries
    /// the account name and the integer day-difference between
    /// account creation and version publication; the policy layer
    /// decides whether `age_days < threshold_days` is actionable.
    MaintainerNewAccount { account: String, age_days: u32 },
    /// The package version was published with npm provenance and
    /// the in-toto subject digest in the DSSE bundle matches the
    /// tarball's `dist.integrity` hash. This is a *structural*
    /// match — it confirms the publisher tied the bundle to this
    /// exact tarball, but does NOT cryptographically verify the
    /// bundle's signature against Sigstore's Fulcio roots
    /// (deferred alongside the keyless-Sigstore slice). Absence is
    /// not suspicious, but presence is a trust boost.
    ProvenanceClaimed { bundle_url: String },
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

    /// Returns the version-surface-change signal if one was recorded.
    /// Tuple is `(previous_version, added_bins, added_scripts)`.
    #[must_use]
    pub fn version_surface_change(&self) -> Option<(&str, &[String], &[String])> {
        self.signals.iter().find_map(|s| match s {
            Signal::VersionSurfaceChange {
                previous_version,
                added_bins,
                added_scripts,
            } => Some((
                previous_version.as_str(),
                added_bins.as_slice(),
                added_scripts.as_slice(),
            )),
            _ => None,
        })
    }

    /// Returns the dist-tag anomaly signal if one was recorded.
    /// Tuple is `(latest_version, highest_published)`.
    #[must_use]
    pub fn dist_tag_anomaly(&self) -> Option<(&str, &str)> {
        self.signals.iter().find_map(|s| match s {
            Signal::DistTagAnomaly {
                latest_version,
                highest_published,
            } => Some((latest_version.as_str(), highest_published.as_str())),
            _ => None,
        })
    }

    /// Returns the name-squat signal if one was recorded.
    /// Tuple is `(style, target)`.
    #[must_use]
    pub fn name_squat(&self) -> Option<(&str, &str)> {
        self.signals.iter().find_map(|s| match s {
            Signal::NameSquat { style, target } => Some((style.as_str(), target.as_str())),
            _ => None,
        })
    }

    /// Returns the maintainer-new-account signal if one was recorded.
    /// Tuple is `(account, age_days)`.
    #[must_use]
    pub fn maintainer_new_account(&self) -> Option<(&str, u32)> {
        self.signals.iter().find_map(|s| match s {
            Signal::MaintainerNewAccount { account, age_days } => {
                Some((account.as_str(), *age_days))
            }
            _ => None,
        })
    }

    /// Returns the provenance-claimed signal if one was recorded.
    /// Returns the bundle URL.
    #[must_use]
    pub fn provenance_claimed(&self) -> Option<&str> {
        self.signals.iter().find_map(|s| match s {
            Signal::ProvenanceClaimed { bundle_url } => Some(bundle_url.as_str()),
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
