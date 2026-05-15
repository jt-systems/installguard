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
    /// Policy required a provenance attestation for this
    /// dependency but no `ProvenanceClaimed` signal was produced
    /// — either the publisher didn't sign, the bundle fetch
    /// failed, or the in-toto subject didn't match
    /// `dist.integrity` (npm) / the Integrity API returned 404
    /// (PyPI). The current gate is structural-only; cryptographic
    /// verification against Sigstore Fulcio is tracked under
    /// ROADMAP M9.
    ProvenanceMissing,
    /// A published security advisory matches this dependency at
    /// or above the policy's severity floor. `id` is the canonical
    /// `<source>:<id>` identifier; `severity` is the bucket that
    /// fired; `source` names the advisory database (so allowlists
    /// can target a specific source).
    AdvisoryKnown {
        id: String,
        severity: String,
        source: String,
    },
    /// Policy required the dependency to declare a license but the
    /// catalogue reported none.
    LicenseMissing {
        source: String,
    },
    /// The catalogue's license declaration is not on the policy's
    /// allowlist. `licenses` is the verbatim list reported by the
    /// catalogue so the operator can copy it into their allowlist
    /// without further lookups.
    LicenseDisallowed {
        licenses: Vec<String>,
        source: String,
    },
    /// Upstream project is marked archived in the catalogue.
    ProjectArchived {
        source: String,
    },
    /// OpenSSF Scorecard score for the upstream repository fell
    /// below the configured floor. `score` is the rounded 0-10
    /// value the catalogue returned; `threshold` is the policy
    /// minimum; `repo` identifies the canonical repo the score
    /// was fetched against; `source` names the catalogue.
    ScorecardBelowThreshold {
        score: u8,
        threshold: u8,
        repo: String,
        source: String,
    },
    /// Aggregate trust score fell below the configured floor.
    /// `score` is the computed value; `threshold` is the policy
    /// minimum. The full per-signal breakdown lives on the
    /// dependency's audit record — this reason carries only the
    /// numeric summary so logs stay grep-able.
    TrustScoreBelowThreshold {
        score: u8,
        threshold: u8,
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
            Self::ProvenanceMissing => "provenance-missing",
            Self::AdvisoryKnown { .. } => "advisory-known",
            Self::LicenseMissing { .. } => "license-missing",
            Self::LicenseDisallowed { .. } => "license-disallowed",
            Self::ProjectArchived { .. } => "project-archived",
            Self::ScorecardBelowThreshold { .. } => "scorecard-below-threshold",
            Self::TrustScoreBelowThreshold { .. } => "trust-score-below-threshold",
            Self::SignalUnavailable { .. } => "signal-unavailable",
        }
    }

    /// Render this reason as a single human-readable English sentence,
    /// suitable for VEX `action_statement` / `impact_statement` fields,
    /// audit-log lines, and PR-comment table cells. The output is
    /// deterministic — no wall-clock or environment input — and is
    /// regression-tested per variant. Stability guarantee from 0.1
    /// onwards: existing variants' wording may be improved between
    /// minor versions but the *meaning* will not change; new variants
    /// add new arms only.
    #[must_use]
    pub fn human_summary(&self) -> String {
        match self {
            Self::ReleaseAgeBelowThreshold {
                observed_minutes,
                required_minutes,
            } => format!(
                "release age {observed_minutes}m below required minimum {required_minutes}m"
            ),
            Self::ExoticSource { kind } => format!("non-registry source: {kind}"),
            Self::DisallowedLifecycleScript { script } => {
                format!("install-time lifecycle script `{script}` declared")
            }
            Self::LifecycleScriptIgnored { script } => format!(
                "lifecycle script `{script}` present but install runs with --ignore-scripts"
            ),
            Self::PublishedAtUnknown => {
                "registry did not return a published-at timestamp".into()
            }
            Self::PublisherChange {
                previous_version,
                previous,
                current,
            } => format!(
                "publisher changed: {previous_version} was published by `{previous}`, current by `{current}`"
            ),
            Self::DeprecatedVersion { message } => match message.as_deref() {
                Some(m) if !m.is_empty() => format!("registry-deprecated: {m}"),
                _ => "registry marked this version deprecated".to_string(),
            },
            Self::SuspiciousScript {
                script,
                pattern,
                excerpt,
            } => format!("lifecycle script `{script}` matched `{pattern}`: {excerpt}"),
            Self::VersionSurfaceChange {
                previous_version,
                added_bins,
                added_scripts,
            } => {
                let mut parts: Vec<String> = Vec::new();
                if !added_bins.is_empty() {
                    parts.push(format!("new bin entries: {}", added_bins.join(", ")));
                }
                if !added_scripts.is_empty() {
                    parts.push(format!(
                        "new lifecycle scripts: {}",
                        added_scripts.join(", ")
                    ));
                }
                format!(
                    "version-surface change vs {previous_version} — {}",
                    parts.join("; ")
                )
            }
            Self::DistTagAnomaly {
                latest_version,
                highest_published,
            } => format!(
                "dist-tag `latest` points to {latest_version} but {highest_published} is published — latest moved backwards"
            ),
            Self::NameSquat { style, target } => {
                format!("package name resembles `{target}` ({style}) — possible typosquat")
            }
            Self::MaintainerNewAccount {
                account,
                age_days,
                threshold_days,
            } => format!(
                "publisher account `{account}` is {age_days}d old (< {threshold_days}d threshold)"
            ),
            Self::ProvenanceMissing => {
                "policy requires cryptographic provenance but none was verified".to_string()
            }
            Self::AdvisoryKnown {
                id,
                severity,
                source,
            } => format!("advisory {id} ({severity}) reported by {source}"),
            Self::LicenseMissing { source } => format!("no license declared in {source}"),
            Self::LicenseDisallowed { licenses, source } => format!(
                "license `{}` (per {source}) is not on the policy allowlist",
                licenses.join(", ")
            ),
            Self::ProjectArchived { source } => {
                format!("upstream project is marked archived in {source}")
            }
            Self::ScorecardBelowThreshold {
                score,
                threshold,
                repo,
                source,
            } => format!(
                "OpenSSF Scorecard {score}/10 for {repo} is below the {threshold} threshold (per {source})"
            ),
            Self::TrustScoreBelowThreshold { score, threshold } => {
                format!("trust score {score}/100 is below the {threshold} threshold")
            }
            Self::SignalUnavailable { provider, reason } => {
                format!("signal provider `{provider}` unavailable: {reason}")
            }
        }
    }

    /// Short, action-oriented hint to render under each finding in
    /// the pretty CLI output. Returns `None` for variants where there
    /// is no useful generic guidance beyond the universal footer
    /// (e.g. `SignalUnavailable` is operational, not actionable per
    /// dependency). Wording stays under ~80 chars so it fits one
    /// terminal line at typical widths.
    #[must_use]
    pub fn remediation(&self) -> Option<&'static str> {
        match self {
            Self::ReleaseAgeBelowThreshold { .. } => {
                Some("wait for the version to age, or pin to the prior release")
            }
            Self::ExoticSource { .. } => {
                Some("prefer a registry version; vendor or fork if you must use this source")
            }
            Self::DisallowedLifecycleScript { .. } => Some(
                "install with --ignore-scripts, or allow this script in `scripts.allow`",
            ),
            Self::LifecycleScriptIgnored { .. } => Some(
                "audit the script before any future `npm rebuild` runs it",
            ),
            Self::PublishedAtUnknown => {
                Some("re-run with cache disabled (`--no-cache`); registry metadata may be stale")
            }
            Self::PublisherChange { .. } => Some(
                "verify the new publisher on the package's npm page before allowing",
            ),
            Self::DeprecatedVersion { .. } => {
                Some("upgrade to a non-deprecated version, or pin to the last good one")
            }
            Self::SuspiciousScript { .. } => Some(
                "treat as suspected supply-chain attack; do NOT install \u{2014} report to npm security",
            ),
            Self::VersionSurfaceChange { .. } => Some(
                "diff the new bins/scripts against the prior version before allowing",
            ),
            Self::DistTagAnomaly { .. } => {
                Some("pin to a specific version; do not rely on the `latest` tag for this package")
            }
            Self::NameSquat { .. } => Some(
                "verify you meant this package, not the popular one it resembles",
            ),
            Self::MaintainerNewAccount { .. } => Some(
                "wait for the account to age, or verify identity out-of-band before allowing",
            ),
            Self::ProvenanceMissing => Some(
                "ask the maintainer to publish with `--provenance`, or relax `provenance.required`",
            ),
            Self::AdvisoryKnown { .. } => {
                Some("upgrade past the affected range, or add the advisory id to `advisories.allow`")
            }
            Self::LicenseMissing { .. } => Some(
                "ask the maintainer to declare a license, or add to `licenses.allow_missing`",
            ),
            Self::LicenseDisallowed { .. } => {
                Some("add the license to `licenses.allow`, or replace the dependency")
            }
            Self::ProjectArchived { .. } => {
                Some("plan a migration; archived projects no longer receive security fixes")
            }
            Self::ScorecardBelowThreshold { .. } => Some(
                "lower `scorecard.min_score`, allowlist this package, or replace it",
            ),
            Self::TrustScoreBelowThreshold { .. } => Some(
                "review the per-signal breakdown in the audit log; tune weights or allowlist",
            ),
            Self::SignalUnavailable { .. } => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive parity test for `Reason::remediation()`. The match
    /// statement below has one arm per variant, so adding a new
    /// `Reason` is a compile error here until its remediation hint is
    /// considered. `SignalUnavailable` is the only variant deliberately
    /// returning `None` (operational failure, not actionable per
    /// dependency); every other variant must return a non-empty hint
    /// short enough to fit one terminal line at typical widths.
    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive enumeration is the point
    fn every_reason_variant_has_a_remediation_or_is_explicitly_none() {
        let samples: Vec<Reason> = vec![
            Reason::ReleaseAgeBelowThreshold {
                observed_minutes: 1,
                required_minutes: 1440,
            },
            Reason::ExoticSource { kind: "git".into() },
            Reason::DisallowedLifecycleScript {
                script: "preinstall".into(),
            },
            Reason::LifecycleScriptIgnored {
                script: "postinstall".into(),
            },
            Reason::PublishedAtUnknown,
            Reason::PublisherChange {
                previous_version: "1.0.0".into(),
                previous: "alice".into(),
                current: "mallory".into(),
            },
            Reason::DeprecatedVersion { message: None },
            Reason::SuspiciousScript {
                script: "postinstall".into(),
                pattern: "curl-pipe-sh".into(),
                excerpt: "curl x | sh".into(),
            },
            Reason::VersionSurfaceChange {
                previous_version: "1.0.0".into(),
                added_bins: vec![],
                added_scripts: vec!["postinstall".into()],
            },
            Reason::DistTagAnomaly {
                latest_version: "0.9.0".into(),
                highest_published: "1.0.0".into(),
            },
            Reason::NameSquat {
                style: "typo".into(),
                target: "react".into(),
            },
            Reason::MaintainerNewAccount {
                account: "x".into(),
                age_days: 1,
                threshold_days: 90,
            },
            Reason::ProvenanceMissing,
            Reason::AdvisoryKnown {
                id: "GHSA-x".into(),
                severity: "critical".into(),
                source: "ghsa".into(),
            },
            Reason::LicenseMissing {
                source: "deps.dev".into(),
            },
            Reason::LicenseDisallowed {
                licenses: vec!["GPL-3.0".into()],
                source: "deps.dev".into(),
            },
            Reason::ProjectArchived {
                source: "deps.dev".into(),
            },
            Reason::ScorecardBelowThreshold {
                score: 3,
                threshold: 6,
                repo: "github.com/o/r".into(),
                source: "openssf-scorecard".into(),
            },
            Reason::TrustScoreBelowThreshold {
                score: 30,
                threshold: 70,
            },
            Reason::SignalUnavailable {
                provider: "osv".into(),
                reason: "503".into(),
            },
        ];

        for r in &samples {
            // Forces the matrix to be exhaustive at compile time:
            // adding a Reason variant without considering its
            // remediation will fail to build here.
            let must_have_hint = match r {
                Reason::SignalUnavailable { .. } => false,
                Reason::ReleaseAgeBelowThreshold { .. }
                | Reason::ExoticSource { .. }
                | Reason::DisallowedLifecycleScript { .. }
                | Reason::LifecycleScriptIgnored { .. }
                | Reason::PublishedAtUnknown
                | Reason::PublisherChange { .. }
                | Reason::DeprecatedVersion { .. }
                | Reason::SuspiciousScript { .. }
                | Reason::VersionSurfaceChange { .. }
                | Reason::DistTagAnomaly { .. }
                | Reason::NameSquat { .. }
                | Reason::MaintainerNewAccount { .. }
                | Reason::ProvenanceMissing
                | Reason::AdvisoryKnown { .. }
                | Reason::LicenseMissing { .. }
                | Reason::LicenseDisallowed { .. }
                | Reason::ProjectArchived { .. }
                | Reason::ScorecardBelowThreshold { .. }
                | Reason::TrustScoreBelowThreshold { .. } => true,
            };
            match (must_have_hint, r.remediation()) {
                (true, Some(hint)) => {
                    assert!(!hint.is_empty(), "{} hint is empty", r.code());
                    assert!(
                        hint.len() <= 100,
                        "{} hint too long for one terminal line: {} chars",
                        r.code(),
                        hint.len()
                    );
                }
                (true, None) => {
                    panic!("{} must have a remediation hint", r.code())
                }
                (false, Some(_)) => {
                    panic!("{} unexpectedly has a remediation hint", r.code())
                }
                (false, None) => {}
            }
        }
    }
}
