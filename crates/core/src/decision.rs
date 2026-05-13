//! Decision model emitted by the policy engine for one dependency.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Structured rationale for a non-`Allow` decision. Free-form strings are
/// deliberately disallowed so audit logs and `installguard.lock` remain
/// machine-readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Reason {
    ReleaseAgeBelowThreshold {
        observed_minutes: i64,
        required_minutes: i64,
    },
    ExoticSource {
        kind: String,
    },
    DisallowedLifecycleScript {
        script: String,
    },
    /// Lifecycle script is present in the package but the project is
    /// installing with `--ignore-scripts`, so the script will not run
    /// during install. A future `npm rebuild` would still execute it.
    LifecycleScriptIgnored {
        script: String,
    },
    PublishedAtUnknown,
    /// The publisher of the resolved version differs from the publisher
    /// of the immediately-prior released version. Carries both
    /// publishers and the previous version so audit logs and `verify`
    /// have enough context to investigate.
    PublisherChange {
        previous_version: String,
        previous: String,
        current: String,
    },
    /// The registry has marked the resolved version as deprecated.
    /// Carries the maintainer-supplied message verbatim when present.
    DeprecatedVersion {
        message: Option<String>,
    },
    /// A lifecycle script body matched a high-risk pattern from
    /// `script_scan` (e.g. `curl ... | sh`, `base64 -d | sh`,
    /// `/dev/tcp` reverse shell). One reason per (script, pattern).
    SuspiciousScript {
        script: String,
        pattern: String,
        excerpt: String,
    },
    /// New executable / lifecycle entry-points appeared between the
    /// immediately-prior released version and the resolved version.
    /// Carries the prior version and the names that are new so audit
    /// logs and `verify` can investigate without re-fetching.
    VersionSurfaceChange {
        previous_version: String,
        added_bins: Vec<String>,
        added_scripts: Vec<String>,
    },
    /// The `latest` dist-tag points to a version strictly older than
    /// the highest non-prerelease published version (“latest moved
    /// backwards”).
    DistTagAnomaly {
        latest_version: String,
        highest_published: String,
    },
    /// The package name is a near-miss for a popular package, by
    /// edit-distance or confusable-codepoint folding. `style` is
    /// `"typo"` or `"homoglyph"` (named `style` to avoid
    /// colliding with serde's enum-tag field).
    NameSquat {
        style: String,
        target: String,
    },
    /// The npm account that published this version was created
    /// fewer than the configured threshold days before the
    /// version's publish time — a strong account-takeover signal.
    MaintainerNewAccount {
        account: String,
        age_days: u32,
        threshold_days: u32,
    },
    SignalUnavailable {
        provider: String,
        reason: String,
    },
}

impl Reason {
    /// Stable kebab-case identifier used to key into the policy's
    /// `severity` map. Matches the serde `code` tag (snake_case) converted
    /// to kebab-case so YAML keys read naturally.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ReleaseAgeBelowThreshold { .. } => "release-age-below-threshold",
            Self::ExoticSource { .. } => "exotic-source",
            Self::DisallowedLifecycleScript { .. } => "disallowed-lifecycle-script",
            Self::LifecycleScriptIgnored { .. } => "lifecycle-script-ignored",
            Self::PublishedAtUnknown => "published-at-unknown",
            Self::PublisherChange { .. } => "publisher-change",
            Self::DeprecatedVersion { .. } => "deprecated-version",
            Self::SuspiciousScript { .. } => "suspicious-script",
            Self::VersionSurfaceChange { .. } => "version-surface-change",
            Self::DistTagAnomaly { .. } => "dist-tag-anomaly",
            Self::NameSquat { .. } => "name-squat",
            Self::MaintainerNewAccount { .. } => "maintainer-new-account",
            Self::SignalUnavailable { .. } => "signal-unavailable",
        }
    }
}

/// Severity assigned to a `Reason` by the policy. `Allow` suppresses the
/// reason entirely; `Warn` records it but does not fail; `Block` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn { reasons: Vec<Reason> },
    Block { reasons: Vec<Reason> },
}

impl Decision {
    #[must_use]
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn { .. } => "warn",
            Self::Block { .. } => "block",
        }
    }
}
