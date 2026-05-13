//! Aggregates a [`SignalSet`] into a single 0–100 trust score with
//! a per-signal breakdown for explainability.
//!
//! ## Design
//!
//! Every dependency starts at **100** (full trust) and accumulates
//! signed deltas as signals are observed. The final value is
//! saturated into `[0, 100]` and rounded to a `u8`. Each delta is
//! recorded as a [`Contribution`] so policy decisions, audit
//! exports and operator UIs can show *why* a score is what it is —
//! a bare number with no provenance is worse than no score at all.
//!
//! ## Weights
//!
//! Weights are deliberately conservative and tuned for **steady-
//! state** signal value, not threat-model precision. They favour
//! transparency over false-confidence: a single risk signal will
//! lower a score but rarely tank it; clusters of signals compound.
//!
//! - `lifecycle_scripts`        −15  (broad attack surface marker)
//! - `suspicious_script`        −35  (high-confidence runtime hazard)
//! - `published_at` (fresh)     −10  (very recent publish)
//! - `publisher_change`         −10  (new maintainer hand-off)
//! - `deprecated_version`       −10  (avoid churn but not a hazard)
//! - `version_surface_change`    −5  (mild novelty)
//! - `dist_tag_anomaly`         −15  (latest pointer anomaly)
//! - `name_squat`               −40  (likely impersonation)
//! - `maintainer_new_account`   −20  (account-takeover signal)
//! - `provenance_claimed`       +10  (structural attestation match)
//! - `unavailable`               −5  (provider couldn't speak)
//!
//! Weights are *not* user-configurable in this slice. Per-policy
//! weight tables are a follow-up; they belong in a separate
//! `trust-weights` slice once we have field data showing which
//! defaults are wrong in practice.

use serde::{Deserialize, Serialize};

use crate::signal::{Signal, SignalSet};

/// A single weighted contribution to a [`TrustScore`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contribution {
    /// Stable kebab-case kind matching the signal serde tag.
    pub signal: String,
    /// Signed delta applied to the running score. Negative
    /// reduces trust; positive increases it.
    pub delta: i16,
    /// Short human-readable rationale for the delta.
    pub rationale: String,
}

/// Aggregate score for one dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustScore {
    /// Saturated final score in `[0, 100]`.
    pub value: u8,
    /// Ordered breakdown of every applied delta. Empty iff no
    /// signals carried weight.
    pub contributions: Vec<Contribution>,
}

impl TrustScore {
    /// Computes a trust score for the given signal set. Pure;
    /// safe to call repeatedly.
    #[must_use]
    pub fn compute(signals: &SignalSet) -> Self {
        let mut running: i32 = 100;
        let mut contributions = Vec::new();
        for signal in &signals.signals {
            let (kind, delta, rationale) = score_signal(signal);
            // Skip neutral signals so the contribution log stays
            // signal (heh) and doesn't fill with zero-weight noise.
            if delta == 0 {
                continue;
            }
            running += i32::from(delta);
            contributions.push(Contribution {
                signal: kind.to_string(),
                delta,
                rationale: rationale.to_string(),
            });
        }
        let value = u8::try_from(running.clamp(0, 100)).unwrap_or(0);
        Self {
            value,
            contributions,
        }
    }
}

fn score_signal(signal: &Signal) -> (&'static str, i16, &'static str) {
    match signal {
        Signal::PublishedAt { .. } => ("published_at", -10, "version was published very recently"),
        Signal::LifecycleScripts { .. } => (
            "lifecycle_scripts",
            -15,
            "lifecycle scripts run code on install",
        ),
        Signal::PublisherChange { .. } => (
            "publisher_change",
            -10,
            "publisher account changed for this version",
        ),
        Signal::DeprecatedVersion { .. } => (
            "deprecated_version",
            -10,
            "version is marked deprecated by the publisher",
        ),
        Signal::SuspiciousScript { .. } => (
            "suspicious_script",
            -35,
            "lifecycle script body matches a suspicious pattern",
        ),
        Signal::VersionSurfaceChange { .. } => (
            "version_surface_change",
            -5,
            "scripts or bin entries changed versus the prior version",
        ),
        Signal::DistTagAnomaly { .. } => (
            "dist_tag_anomaly",
            -15,
            "dist-tag points at an unexpected version",
        ),
        Signal::NameSquat { .. } => (
            "name_squat",
            -40,
            "package name resembles a popular package",
        ),
        Signal::MaintainerNewAccount { .. } => (
            "maintainer_new_account",
            -20,
            "publisher account is unusually young",
        ),
        Signal::ProvenanceClaimed { .. } => (
            "provenance_claimed",
            10,
            "publisher signed a provenance bundle matching this tarball",
        ),
        Signal::Unavailable { .. } => ("unavailable", -5, "signal provider was unable to respond"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn empty_signal_set_scores_full_trust() {
        let s = SignalSet::default();
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 100);
        assert!(score.contributions.is_empty());
    }

    #[test]
    fn risk_signals_subtract() {
        let mut s = SignalSet::default();
        s.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        s.push(Signal::DeprecatedVersion { message: None });
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 75); // 100 - 15 - 10
        assert_eq!(score.contributions.len(), 2);
    }

    #[test]
    fn provenance_adds_back_trust() {
        let mut s = SignalSet::default();
        s.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        s.push(Signal::ProvenanceClaimed {
            bundle_url: "u".into(),
        });
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 95); // 100 - 15 + 10
    }

    #[test]
    fn score_saturates_at_zero() {
        let mut s = SignalSet::default();
        // Stack enough negatives to bottom out.
        s.push(Signal::NameSquat {
            style: "typo".into(),
            target: "react".into(),
        });
        s.push(Signal::SuspiciousScript {
            script: "postinstall".into(),
            pattern: "curl-pipe-shell".into(),
            excerpt: "x".into(),
        });
        s.push(Signal::MaintainerNewAccount {
            account: "alice".into(),
            age_days: 1,
        });
        s.push(Signal::PublisherChange {
            previous_version: "0.9.0".into(),
            previous: "a".into(),
            current: "b".into(),
        });
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 0);
    }

    #[test]
    fn score_saturates_at_hundred() {
        // Synthetic: many positives, no negatives — capped at 100.
        let mut s = SignalSet::default();
        for _ in 0..20 {
            s.push(Signal::ProvenanceClaimed {
                bundle_url: "u".into(),
            });
        }
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 100);
    }

    #[test]
    fn published_at_carries_weight() {
        let mut s = SignalSet::default();
        s.push(Signal::PublishedAt { at: Utc::now() });
        let score = TrustScore::compute(&s);
        assert_eq!(score.value, 90);
    }
}
