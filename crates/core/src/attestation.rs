//! in-toto Attestation Framework v1 wrapper for InstallGuard policy
//! evaluations.
//!
//! Emits a `Statement` whose `subject` is the evaluated lockfile (by
//! sha256) and whose `predicate` is the full `InstallguardLock`. The
//! predicate type URI is **`https://installguard.dev/policy-evaluation/v1`**
//! and is the on-the-wire identifier consumers should match on.
//!
//! The statement is *unsigned*. Pair with cosign / Sigstore (or any
//! DSSE signer) to produce a signed bundle; the unsigned form is still
//! useful as a deterministic build artefact and as the payload that
//! gets wrapped by DSSE.
//!
//! References:
//! * <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
//! * <https://slsa.dev/attestation-model>

use serde::{Deserialize, Serialize};

use crate::lockfile::{InstallguardLock, LockError};

/// in-toto Statement v1 type URI.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Predicate type URI for InstallGuard policy evaluations. Bump the
/// version suffix on any breaking change to the lock schema.
pub const PREDICATE_TYPE: &str = "https://installguard.dev/policy-evaluation/v1";

/// in-toto Statement: subject + predicate envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: InstallguardLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: DigestSet,
}

/// Map of digest algorithm name -> hex-encoded digest. in-toto requires
/// at least one entry; we always emit `sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestSet {
    pub sha256: String,
}

impl Statement {
    /// Build an unsigned Statement from a finished lock. Subject name is
    /// the project-relative lockfile path; subject sha256 mirrors the
    /// lock's `lockfile_digest`.
    #[must_use]
    pub fn from_lock(lock: InstallguardLock) -> Self {
        let subject = Subject {
            name: lock.lockfile.clone(),
            digest: DigestSet {
                sha256: lock.lockfile_digest.clone(),
            },
        };
        Self {
            type_: STATEMENT_TYPE.to_string(),
            subject: vec![subject],
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate: lock,
        }
    }

    /// Pretty-printed JSON with a trailing newline.
    pub fn to_json(&self) -> Result<String, LockError> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }

    pub fn from_json(raw: &str) -> Result<Self, LockError> {
        Ok(serde_json::from_str(raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{LockSummary, ToolInfo};
    use chrono::TimeZone;

    fn sample_lock() -> InstallguardLock {
        InstallguardLock {
            schema_version: 1,
            tool: ToolInfo {
                name: "installguard".into(),
                version: "0.0.0".into(),
            },
            generated_at: chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            adapter: "npm".into(),
            lockfile: "package-lock.json".into(),
            lockfile_digest: "deadbeef".repeat(8),
            policy_digest: "feedface".repeat(8),
            summary: LockSummary {
                total: 0,
                allow: 0,
                warn: 0,
                block: 0,
            },
            decisions: vec![],
        }
    }

    #[test]
    fn statement_subject_mirrors_lockfile() {
        let s = Statement::from_lock(sample_lock());
        assert_eq!(s.type_, STATEMENT_TYPE);
        assert_eq!(s.predicate_type, PREDICATE_TYPE);
        assert_eq!(s.subject.len(), 1);
        assert_eq!(s.subject[0].name, "package-lock.json");
        assert_eq!(s.subject[0].digest.sha256, "deadbeef".repeat(8));
    }

    #[test]
    fn round_trip() {
        let s = Statement::from_lock(sample_lock());
        let json = s.to_json().unwrap();
        let back = Statement::from_json(&json).unwrap();
        assert_eq!(s, back);
    }
}
