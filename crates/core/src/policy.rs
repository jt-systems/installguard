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
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct DirectOverrides {
    pub minimum_release_age: Option<i64>,
    /// Per-direct-dep override for [`Defaults::detect_publisher_change`].
    /// When `Some(_)`, takes precedence for direct deps.
    pub detect_publisher_change: Option<bool>,
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
    pub fn evaluate_with(
        &self,
        dep: &ResolvedDependency,
        signals: &SignalSet,
        now: DateTime<Utc>,
        ctx: EvalContext,
    ) -> Decision {
        let mut reasons: Vec<Reason> = Vec::new();

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

    /// Resolve the effective severity for a reason. Defaults are `Block`
    /// for everything except [`Reason::LifecycleScriptIgnored`], which
    /// defaults to `Warn` (the script can't run during install but a later
    /// `npm rebuild` would). The policy's `severity` map overrides either.
    fn severity_for(&self, r: &Reason) -> Severity {
        if let Some(s) = self.severity.get(r.code()).copied() {
            return s;
        }
        match r {
            Reason::LifecycleScriptIgnored { .. } => Severity::Warn,
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

    fn script_allowed(&self, package: &str, _script: &str) -> bool {
        match self.scripts.policy {
            ScriptPolicy::AllowByDefault => true,
            ScriptPolicy::DenyByDefault => self.scripts.allow.iter().any(|p| p == package),
        }
    }
}

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
        let p = Policy::from_yaml(
            "policyVersion: 1\nscripts:\n  policy: deny-by-default\n  allow: [esbuild]\n",
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
            &dep("esbuild", true, Source::Registry { url: "x".into() }),
            &signals,
            Utc::now(),
        );
        assert!(matches!(allowed, Decision::Allow));
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
}
