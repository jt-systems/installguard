//! Deterministic lock-file format for InstallGuard policy evaluations.
//!
//! `installguard.lock` is a JSON document that captures *the inputs and the
//! result* of a policy run in a form that:
//!
//! * is byte-stable across machines (sorted keys, sorted entries, no host
//!   identifiers, no wall-clock noise in the identity-bearing fields), and
//! * lets a downstream consumer re-verify the same decisions offline
//!   (`installguard verify` / `--frozen-policy`), or feed an attestation
//!   predicate (`policy-evaluation/v1`) without re-evaluating signals.
//!
//! Identity hashing intentionally excludes the human-readable
//! `generated_at` timestamp so that two runs with identical inputs produce
//! a digest-stable artifact.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decision::{Decision, Reason};
use crate::dependency::{ResolvedDependency, Source};
use crate::policy::Policy;
use crate::signal::{Signal, SignalSet};

/// Current schema version of `installguard.lock`. Bump on breaking changes.
pub const LOCK_SCHEMA_VERSION: u32 = 1;

/// Top-level lock file. Field order matches serialised output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallguardLock {
    pub schema_version: u32,
    pub tool: ToolInfo,
    /// Wall-clock timestamp of generation. **Not** included in `digest()`.
    pub generated_at: DateTime<Utc>,
    pub adapter: String,
    /// Project-relative path to the lockfile that was evaluated.
    pub lockfile: String,
    /// SHA-256 of the lockfile bytes, hex-encoded.
    pub lockfile_digest: String,
    /// SHA-256 of the canonicalised policy JSON, hex-encoded.
    pub policy_digest: String,
    pub summary: LockSummary,
    /// Decisions sorted lexicographically by `(name, version)` for stable
    /// output regardless of input traversal order.
    pub decisions: Vec<LockDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSummary {
    pub total: usize,
    pub allow: usize,
    pub warn: usize,
    pub block: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockDecision {
    pub name: String,
    pub version: String,
    pub direct: bool,
    /// Stable identifier for the source kind (e.g. `registry`, `git`,
    /// `tarball`). Full source detail is intentionally omitted to keep the
    /// lock file small and to avoid coupling to URL formatting churn.
    pub source: String,
    pub decision: String,
    /// Reasons sorted by `code` for determinism.
    pub reasons: Vec<Reason>,
    /// Sorted, deduplicated signal `kind`s observed for this dependency.
    /// Timestamp-bearing signal payloads are intentionally elided so the
    /// lock stays stable across re-runs that hit the same registry tag.
    pub signal_kinds: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported lock schema version: {0}")]
    UnsupportedVersion(u32),
}

/// Inputs needed to materialise a `LockDecision`. Borrowed from the caller
/// to avoid cloning the dependency / signal set.
#[derive(Debug)]
pub struct LockEntry<'a> {
    pub dep: &'a ResolvedDependency,
    pub signals: &'a SignalSet,
    pub decision: &'a Decision,
}

impl InstallguardLock {
    /// Build a lock from evaluation results plus the policy + lockfile bytes
    /// that produced them.
    pub fn build(
        adapter_id: &str,
        lockfile_path: &str,
        lockfile_bytes: &[u8],
        policy: &Policy,
        entries: &[LockEntry<'_>],
        generated_at: DateTime<Utc>,
        tool_version: &str,
    ) -> Result<Self, LockError> {
        let mut decisions: Vec<LockDecision> = entries.iter().map(|e| build_decision(e)).collect();
        decisions.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

        let summary = LockSummary {
            total: decisions.len(),
            allow: decisions.iter().filter(|d| d.decision == "allow").count(),
            warn: decisions.iter().filter(|d| d.decision == "warn").count(),
            block: decisions.iter().filter(|d| d.decision == "block").count(),
        };

        Ok(Self {
            schema_version: LOCK_SCHEMA_VERSION,
            tool: ToolInfo {
                name: "installguard".into(),
                version: tool_version.into(),
            },
            generated_at,
            adapter: adapter_id.into(),
            lockfile: lockfile_path.into(),
            lockfile_digest: hex_sha256(lockfile_bytes),
            policy_digest: policy_digest(policy)?,
            summary,
            decisions,
        })
    }

    /// Serialise to the canonical on-disk JSON: pretty-printed, BTreeMap-
    /// sorted via the default serde_json behaviour for `Map<String, _>`,
    /// trailing newline.
    pub fn to_json(&self) -> Result<String, LockError> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }

    pub fn from_json(raw: &str) -> Result<Self, LockError> {
        let lock: Self = serde_json::from_str(raw)?;
        if lock.schema_version != LOCK_SCHEMA_VERSION {
            return Err(LockError::UnsupportedVersion(lock.schema_version));
        }
        Ok(lock)
    }

    /// Stable digest of the lock's *identity*: every field except the
    /// human-readable `generated_at` timestamp. Two runs with identical
    /// inputs MUST produce the same digest.
    pub fn digest(&self) -> String {
        // Build a normalised map ourselves to drop `generated_at`.
        let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        map.insert("schema_version", serde_json::json!(self.schema_version));
        map.insert("tool", serde_json::to_value(&self.tool).unwrap_or_default());
        map.insert("adapter", serde_json::json!(self.adapter));
        map.insert("lockfile", serde_json::json!(self.lockfile));
        map.insert("lockfile_digest", serde_json::json!(self.lockfile_digest));
        map.insert("policy_digest", serde_json::json!(self.policy_digest));
        map.insert(
            "summary",
            serde_json::to_value(&self.summary).unwrap_or_default(),
        );
        map.insert(
            "decisions",
            serde_json::to_value(&self.decisions).unwrap_or_default(),
        );
        let canonical = serde_json::to_vec(&map).unwrap_or_default();
        hex_sha256(&canonical)
    }

    /// Compare two lock files for verification. Returns `Ok(())` when the
    /// digests match, otherwise a structured diff suitable for CLI output.
    pub fn verify_against(&self, other: &Self) -> Result<(), LockMismatch> {
        if self.digest() == other.digest() {
            return Ok(());
        }
        let mut diffs = Vec::new();
        if self.lockfile_digest != other.lockfile_digest {
            diffs.push(format!(
                "lockfile changed (was {}, now {})",
                short(&other.lockfile_digest),
                short(&self.lockfile_digest)
            ));
        }
        if self.policy_digest != other.policy_digest {
            diffs.push(format!(
                "policy changed (was {}, now {})",
                short(&other.policy_digest),
                short(&self.policy_digest)
            ));
        }
        let by_key = |d: &LockDecision| (d.name.clone(), d.version.clone());
        let cur: BTreeMap<_, _> = self.decisions.iter().map(|d| (by_key(d), d)).collect();
        let prev: BTreeMap<_, _> = other.decisions.iter().map(|d| (by_key(d), d)).collect();
        for (k, v) in &cur {
            match prev.get(k) {
                None => diffs.push(format!("added: {}@{} -> {}", k.0, k.1, v.decision)),
                Some(p) if p.decision != v.decision => {
                    diffs.push(format!("{}@{}: {} -> {}", k.0, k.1, p.decision, v.decision));
                }
                _ => {}
            }
        }
        for k in prev.keys() {
            if !cur.contains_key(k) {
                diffs.push(format!("removed: {}@{}", k.0, k.1));
            }
        }
        if diffs.is_empty() {
            // Digests differ but all decisions match — likely a reason or
            // signal-set drift. Fall back to a generic message.
            diffs.push("digest mismatch (signal or reason details changed)".into());
        }
        Err(LockMismatch { diffs })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("installguard.lock verification failed:\n  - {}", diffs.join("\n  - "))]
pub struct LockMismatch {
    pub diffs: Vec<String>,
}

fn build_decision(e: &LockEntry<'_>) -> LockDecision {
    let (decision, mut reasons) = match e.decision {
        Decision::Allow => ("allow", Vec::new()),
        Decision::Warn { reasons } => ("warn", reasons.clone()),
        Decision::Block { reasons } => ("block", reasons.clone()),
    };
    reasons.sort_by(|a, b| a.code().cmp(b.code()));

    let mut kinds: Vec<String> = e.signals.signals.iter().map(signal_kind).collect();
    kinds.sort();
    kinds.dedup();

    LockDecision {
        name: e.dep.name.clone(),
        version: e.dep.version.clone(),
        direct: e.dep.direct,
        source: source_kind(&e.dep.source).to_string(),
        decision: decision.to_string(),
        reasons,
        signal_kinds: kinds,
    }
}

fn signal_kind(s: &Signal) -> String {
    match s {
        Signal::PublishedAt { .. } => "published_at",
        Signal::LifecycleScripts { .. } => "lifecycle_scripts",
        Signal::Unavailable { .. } => "unavailable",
    }
    .to_string()
}

fn source_kind(s: &Source) -> &'static str {
    match s {
        Source::Registry { .. } => "registry",
        Source::Git { .. } => "git",
        Source::GithubShortcut { .. } => "github",
        Source::Tarball { .. } => "tarball",
        Source::File { .. } => "file",
        Source::Workspace => "workspace",
    }
}

fn policy_digest(policy: &Policy) -> Result<String, LockError> {
    // Round-trip through serde_json::Value so that every map key is sorted
    // (BTreeMap-backed) and the byte form is stable.
    let value = serde_json::to_value(policy)?;
    let canonical = serde_json::to_vec(&value)?;
    Ok(hex_sha256(&canonical))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Ecosystem, Source};
    use crate::signal::Signal;

    fn dep(name: &str, ver: &str) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: ver.into(),
            integrity: None,
            source: Source::Registry {
                url: format!("https://registry.npmjs.org/{name}"),
            },
            direct: true,
            requested_by: Vec::new(),
        }
    }

    fn signals_with_published() -> SignalSet {
        SignalSet {
            signals: vec![Signal::PublishedAt {
                at: chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            }],
        }
    }

    use chrono::TimeZone;

    fn build_two(
        reasons_a: Vec<Reason>,
        reasons_b: Vec<Reason>,
    ) -> (InstallguardLock, InstallguardLock) {
        let policy = Policy::default();
        let now1 = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap();
        let now2 = chrono::Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap();
        let d_a = dep("a", "1.0.0");
        let d_b = dep("b", "2.0.0");
        let s = signals_with_published();
        let dec_a = if reasons_a.is_empty() {
            Decision::Allow
        } else {
            Decision::Block { reasons: reasons_a }
        };
        let dec_b = if reasons_b.is_empty() {
            Decision::Allow
        } else {
            Decision::Block { reasons: reasons_b }
        };
        let entries = vec![
            LockEntry {
                dep: &d_a,
                signals: &s,
                decision: &dec_a,
            },
            LockEntry {
                dep: &d_b,
                signals: &s,
                decision: &dec_b,
            },
        ];
        let lock1 = InstallguardLock::build(
            "npm",
            "package-lock.json",
            b"raw bytes",
            &policy,
            &entries,
            now1,
            "0.0.0",
        )
        .unwrap();
        let lock2 = InstallguardLock::build(
            "npm",
            "package-lock.json",
            b"raw bytes",
            &policy,
            &entries,
            now2,
            "0.0.0",
        )
        .unwrap();
        (lock1, lock2)
    }

    #[test]
    fn digest_excludes_generated_at() {
        let (l1, l2) = build_two(vec![], vec![]);
        assert_ne!(l1.generated_at, l2.generated_at);
        assert_eq!(l1.digest(), l2.digest());
    }

    #[test]
    fn round_trip_is_stable() {
        let (l1, _) = build_two(vec![], vec![]);
        let json = l1.to_json().unwrap();
        let l1b = InstallguardLock::from_json(&json).unwrap();
        assert_eq!(l1, l1b);
        // Re-serialising must produce identical bytes.
        assert_eq!(json, l1b.to_json().unwrap());
    }

    #[test]
    fn decisions_are_sorted_by_name() {
        // Build with reversed order; lock should still be sorted.
        let policy = Policy::default();
        let now = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let d_a = dep("a", "1.0.0");
        let d_b = dep("b", "2.0.0");
        let s = signals_with_published();
        let dec = Decision::Allow;
        let entries = vec![
            LockEntry {
                dep: &d_b,
                signals: &s,
                decision: &dec,
            },
            LockEntry {
                dep: &d_a,
                signals: &s,
                decision: &dec,
            },
        ];
        let lock = InstallguardLock::build("npm", "p.json", b"x", &policy, &entries, now, "0.0.0")
            .unwrap();
        assert_eq!(lock.decisions[0].name, "a");
        assert_eq!(lock.decisions[1].name, "b");
    }

    #[test]
    fn verify_detects_decision_change() {
        let (mut clean, _) = build_two(vec![], vec![]);
        let (dirty, _) = build_two(
            vec![Reason::DisallowedLifecycleScript {
                script: "postinstall".into(),
            }],
            vec![],
        );
        // Force same generated_at so the only diff is the decision.
        clean.generated_at = dirty.generated_at;
        let err = dirty.verify_against(&clean).unwrap_err();
        assert!(
            err.diffs
                .iter()
                .any(|d| d.contains("a@1.0.0") && d.contains("block")),
            "diffs={:?}",
            err.diffs
        );
    }

    #[test]
    fn verify_detects_lockfile_drift() {
        let policy = Policy::default();
        let now = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let d_a = dep("a", "1.0.0");
        let s = signals_with_published();
        let dec = Decision::Allow;
        let entries = vec![LockEntry {
            dep: &d_a,
            signals: &s,
            decision: &dec,
        }];
        let l1 = InstallguardLock::build("npm", "p.json", b"v1", &policy, &entries, now, "0.0.0")
            .unwrap();
        let l2 = InstallguardLock::build("npm", "p.json", b"v2", &policy, &entries, now, "0.0.0")
            .unwrap();
        let err = l2.verify_against(&l1).unwrap_err();
        assert!(
            err.diffs.iter().any(|d| d.contains("lockfile changed")),
            "diffs={:?}",
            err.diffs
        );
    }
}
