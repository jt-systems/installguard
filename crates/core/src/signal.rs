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
    /// A published security advisory matches this exact dependency
    /// version. One signal per advisory; multiple advisories on
    /// the same package produce multiple signals so audit logs
    /// retain the full set. `id` is the canonical identifier in
    /// `<source>:<id>` form (e.g. `"OSV:GHSA-xxxx-xxxx-xxxx"`),
    /// `severity` is the lowercased CVSS bucket
    /// (`low|medium|high|critical|unknown`), `summary` is the
    /// short human-readable headline straight from the advisory,
    /// and `source` names the provider that produced it (so
    /// downstream UIs can group / dedupe by source).
    AdvisoryKnown {
        id: String,
        severity: String,
        summary: String,
        source: String,
    },
    /// Project-level metadata pulled from a third-party catalogue
    /// (deps.dev today; pluggable in principle). `licenses` is the
    /// SPDX expression list the catalogue records for the version
    /// (lowercased / left as-published; we do not normalise SPDX
    /// here — that's a license-allowlist concern). `archived`
    /// reflects whether the catalogue marks the upstream project
    /// as archived; `None` when the catalogue exposes no archive
    /// status. `source` names the catalogue (`"deps.dev"`).
    ProjectMetadata {
        licenses: Vec<String>,
        archived: Option<bool>,
        source: String,
    },
    /// The package version was published with npm provenance and
    /// the in-toto subject digest in the DSSE bundle matches the
    /// tarball's `dist.integrity` hash. This is a *structural*
    /// match — it confirms the publisher tied the bundle to this
    /// exact tarball, but does NOT cryptographically verify the
    /// bundle's signature against Sigstore's Fulcio roots
    /// (deferred alongside the keyless-Sigstore slice). Absence is
    /// not suspicious, but presence is a trust boost.
    ProvenanceClaimed { bundle_url: String },
    /// OpenSSF Scorecard aggregate score for the upstream
    /// project on a 0-10 scale (rounded to one decimal in the
    /// upstream API; we round to nearest integer for stable
    /// policy comparison). `repo` is the canonical
    /// `host/owner/repo` triple the score was fetched against
    /// (e.g. `"github.com/expressjs/express"`); kept verbatim so
    /// audit logs can re-fetch. `source` is the catalogue
    /// (`"openssf-scorecard"`).
    ScorecardScore {
        score: u8,
        repo: String,
        source: String,
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

    /// Returns every advisory signal recorded for this dependency,
    /// in the order the provider produced them. Empty when no
    /// advisory matches.
    #[must_use]
    pub fn advisories(&self) -> Vec<(&str, &str, &str, &str)> {
        self.signals
            .iter()
            .filter_map(|s| match s {
                Signal::AdvisoryKnown {
                    id,
                    severity,
                    summary,
                    source,
                } => Some((
                    id.as_str(),
                    severity.as_str(),
                    summary.as_str(),
                    source.as_str(),
                )),
                _ => None,
            })
            .collect()
    }

    /// Returns the project-metadata signal if one was recorded.
    /// Tuple is `(licenses, archived, source)`.
    #[must_use]
    pub fn project_metadata(&self) -> Option<(&[String], Option<bool>, &str)> {
        self.signals.iter().find_map(|s| match s {
            Signal::ProjectMetadata {
                licenses,
                archived,
                source,
            } => Some((licenses.as_slice(), *archived, source.as_str())),
            _ => None,
        })
    }

    /// Returns the OpenSSF Scorecard signal if one was recorded.
    /// Tuple is `(score, repo, source)`.
    #[must_use]
    pub fn scorecard(&self) -> Option<(u8, &str, &str)> {
        self.signals.iter().find_map(|s| match s {
            Signal::ScorecardScore {
                score,
                repo,
                source,
            } => Some((*score, repo.as_str(), source.as_str())),
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

/// Plugin contract for third-party signal providers.
///
/// # Stability
///
/// `SignalProvider` is a **public extension point**. From v0.1
/// onwards we treat the trait's surface (method names, signatures
/// and error type) as semver-stable: additive changes only,
/// breaking changes will go through a major-version bump and a
/// deprecation cycle. The [`Signal`] enum is `#[non_exhaustive]`
/// in spirit (matched ergonomically by always providing a
/// catch-all in the policy / trust-score layers); new variants
/// may be added in minor releases and downstream providers should
/// be tolerant of receiving signals they did not produce.
///
/// # Implementing a provider
///
/// 1. Add a dependency on `installguard-core` matching your
///    target runtime version.
/// 2. Define a `pub struct YourProvider` carrying any clients,
///    caches or configuration the provider needs.
/// 3. Implement [`SignalProvider`]. `id()` should return a
///    stable kebab- or snake-case identifier (audit logs and
///    trust-score breakdowns key off it). `supports()` is called
///    cheaply and frequently — keep it allocation-free.
/// 4. Wire your provider into the host (today: a static
///    [`crate::CompositeProvider`] composition; M7+ may add a
///    discovery-and-verification loader).
///
/// See `crates/core/examples/minimal_provider.rs` for a complete
/// 30-line example.
///
/// # Error handling
///
/// Returning `Err(_)` from [`SignalProvider::signals`] is
/// reserved for genuine *infrastructure* failure (network down,
/// catalogue 5xx, decode error). When a provider can simply
/// produce no signals for a dependency it should return
/// `Ok(Vec::new())` — the absence of a signal is not an error.
/// Hosts that fan out across multiple providers (e.g.
/// [`crate::CompositeProvider`]) translate `Err(_)` into a
/// [`Signal::Unavailable`] so partial degradation is observable
/// without crashing the whole evaluation.
///
/// Implementations live in `crates/signals/<id>/` for the
/// built-in providers; third-party providers may live anywhere.
#[async_trait::async_trait]
pub trait SignalProvider: Send + Sync {
    /// Stable identifier, used for audit logs and cache keys.
    /// Conventionally kebab- or snake-case; must remain
    /// constant across runs of the same provider version.
    fn id(&self) -> &'static str;
    /// Returns `true` iff this provider can produce signals for
    /// the given dependency. Called frequently; keep cheap.
    fn supports(&self, dep: &ResolvedDependency) -> bool;
    /// Produces signals for a single dependency. See the trait-
    /// level docs on error handling — `Ok(vec![])` is the right
    /// answer for "I have nothing to say"; `Err(_)` is reserved
    /// for infrastructure failure.
    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError>;
}

/// Forwarding impl so callers can store providers behind a
/// `Box<dyn SignalProvider>` and still hand them to generic
/// wrappers (e.g. `CachedProvider<P>`). Without this the
/// composite + cache layering wouldn't type-check.
#[async_trait::async_trait]
impl<T: SignalProvider + ?Sized> SignalProvider for Box<T> {
    fn id(&self) -> &'static str {
        (**self).id()
    }
    fn supports(&self, dep: &ResolvedDependency) -> bool {
        (**self).supports(dep)
    }
    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        (**self).signals(dep).await
    }
}
