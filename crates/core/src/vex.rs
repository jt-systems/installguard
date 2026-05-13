//! OpenVEX 0.2.0 emitter for an InstallGuard evaluation.
//!
//! VEX (Vulnerability EXchange) is normally about CVEs and "is my
//! product affected". InstallGuard repurposes the same envelope for
//! *install-time policy reasons* (lifecycle scripts, exotic sources,
//! release-age, etc.) so consumers that already ingest VEX can route
//! InstallGuard findings through the same pipeline.
//!
//! Mapping:
//!
//! * One `Statement` per `(package, reason)` pair. A package with two
//!   reasons produces two statements; a package with no reasons (an
//!   `Allow` decision) produces zero.
//! * `vulnerability.@id` = `https://installguard.dev/reasons/<code>`
//!   (e.g. `.../disallowed-lifecycle-script`).
//! * `vulnerability.name` = the kebab-case reason code.
//! * `products[].@id` = the dependency's purl (same string the SBOM uses).
//! * `status` mapping:
//!     - `Block` → `affected`
//!     - `Warn`  → `under_investigation`
//!     - `Allow` → not emitted (no reasons to attest to)
//! * `action_statement` (block) / `impact_statement` (warn) carry a
//!   short human-readable summary derived from the `Reason`.
//!
//! Output is byte-stable: statements sorted by
//! `(vulnerability.name, products[0].@id)`, no wall-clock noise in
//! identity-bearing fields, deterministic `@id` URN.
//!
//! Reference: <https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md>

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::decision::{Decision, Reason};
use crate::dependency::ResolvedDependency;
use crate::sbom::purl_for;

/// OpenVEX JSON-LD context URI for the version we emit. Consumers pin
/// on this; bump deliberately.
pub const CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

/// Author string baked into every document. Configurable by the caller
/// via `Vex::build_with_author`; this is the default.
pub const DEFAULT_AUTHOR: &str = "InstallGuard";

/// URI prefix for InstallGuard reason "vulnerability" identifiers.
pub const REASON_URI_PREFIX: &str = "https://installguard.dev/reasons/";

/// Top-level OpenVEX 0.2.0 document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vex {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    pub id: String,
    pub author: String,
    pub timestamp: DateTime<Utc>,
    pub version: u32,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub vulnerability: Vulnerability,
    pub products: Vec<Product>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_statement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(rename = "@id")]
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    #[serde(rename = "@id")]
    pub id: String,
}

/// OpenVEX status values. Lower-case + snake_case on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

/// One row of input to `Vex::build`.
#[derive(Debug, Clone, Copy)]
pub struct VexEntry<'a> {
    pub dep: &'a ResolvedDependency,
    pub decision: &'a Decision,
}

impl Vex {
    /// Build a deterministic OpenVEX 0.2.0 document. `lockfile_digest`
    /// drives the document `@id` so identical inputs produce identical
    /// `@id` values.
    #[must_use]
    pub fn build(
        entries: &[VexEntry<'_>],
        lockfile_digest: &str,
        generated_at: DateTime<Utc>,
    ) -> Self {
        Self::build_with_author(entries, lockfile_digest, generated_at, DEFAULT_AUTHOR)
    }

    #[must_use]
    pub fn build_with_author(
        entries: &[VexEntry<'_>],
        lockfile_digest: &str,
        generated_at: DateTime<Utc>,
        author: &str,
    ) -> Self {
        let mut statements: Vec<Statement> = entries
            .iter()
            .flat_map(|e| statements_for(e.dep, e.decision))
            .collect();
        statements.sort_by(|a, b| {
            a.vulnerability
                .name
                .cmp(&b.vulnerability.name)
                .then_with(|| a.products[0].id.cmp(&b.products[0].id))
        });
        statements.dedup();

        Self {
            context: CONTEXT.to_string(),
            id: format!("https://installguard.dev/vex/{lockfile_digest}"),
            author: author.to_string(),
            timestamp: generated_at,
            version: 1,
            statements,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }
}

fn statements_for(dep: &ResolvedDependency, decision: &Decision) -> Vec<Statement> {
    let (status, reasons): (Status, &[Reason]) = match decision {
        Decision::Allow => return Vec::new(),
        Decision::Warn { reasons } => (Status::UnderInvestigation, reasons),
        Decision::Block { reasons } => (Status::Affected, reasons),
    };
    let purl = purl_for(dep);
    reasons
        .iter()
        .map(|r| {
            let code = r.code();
            let summary = summarise(r);
            Statement {
                vulnerability: Vulnerability {
                    id: format!("{REASON_URI_PREFIX}{code}"),
                    name: code.to_string(),
                },
                products: vec![Product { id: purl.clone() }],
                status,
                action_statement: matches!(status, Status::Affected).then(|| summary.clone()),
                impact_statement: matches!(status, Status::UnderInvestigation).then_some(summary),
            }
        })
        .collect()
}

fn summarise(r: &Reason) -> String {
    match r {
        Reason::ReleaseAgeBelowThreshold {
            observed_minutes,
            required_minutes,
        } => format!("release age {observed_minutes}m below required minimum {required_minutes}m"),
        Reason::ExoticSource { kind } => format!("non-registry source: {kind}"),
        Reason::DisallowedLifecycleScript { script } => {
            format!("install-time lifecycle script `{script}` declared")
        }
        Reason::LifecycleScriptIgnored { script } => {
            format!("lifecycle script `{script}` present but install runs with --ignore-scripts")
        }
        Reason::PublishedAtUnknown => "registry did not return a published-at timestamp".into(),
        Reason::PublisherChange {
            previous_version,
            previous,
            current,
        } => format!(
            "publisher changed: {previous_version} was published by `{previous}`, current by `{current}`"
        ),
        Reason::DeprecatedVersion { message } => match message.as_deref() {
            Some(m) if !m.is_empty() => format!("registry-deprecated: {m}"),
            _ => "registry marked this version deprecated".to_string(),
        },
        Reason::SuspiciousScript {
            script,
            pattern,
            excerpt,
        } => format!("lifecycle script `{script}` matched `{pattern}`: {excerpt}"),
        Reason::SignalUnavailable { provider, reason } => {
            format!("signal provider `{provider}` unavailable: {reason}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Ecosystem, Source};

    fn dep(name: &str, version: &str) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            integrity: None,
            source: Source::Registry { url: String::new() },
            direct: true,
            requested_by: Vec::new(),
        }
    }

    fn ts() -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn allow_emits_no_statements() {
        let d = dep("a", "1");
        let dec = Decision::Allow;
        let vex = Vex::build(
            &[VexEntry {
                dep: &d,
                decision: &dec,
            }],
            &"0".repeat(64),
            ts(),
        );
        assert!(vex.statements.is_empty());
    }

    #[test]
    fn block_maps_to_affected_with_action_statement() {
        let d = dep("esbuild", "0.21.5");
        let dec = Decision::Block {
            reasons: vec![Reason::DisallowedLifecycleScript {
                script: "preinstall".into(),
            }],
        };
        let vex = Vex::build(
            &[VexEntry {
                dep: &d,
                decision: &dec,
            }],
            &"a".repeat(64),
            ts(),
        );
        assert_eq!(vex.statements.len(), 1);
        let s = &vex.statements[0];
        assert_eq!(s.status, Status::Affected);
        assert_eq!(s.vulnerability.name, "disallowed-lifecycle-script");
        assert_eq!(s.products[0].id, "pkg:npm/esbuild@0.21.5");
        assert!(s.action_statement.is_some());
        assert!(s.impact_statement.is_none());
    }

    #[test]
    fn warn_maps_to_under_investigation_with_impact_statement() {
        let d = dep("left-pad", "1.3.0");
        let dec = Decision::Warn {
            reasons: vec![Reason::ReleaseAgeBelowThreshold {
                observed_minutes: 10,
                required_minutes: 1440,
            }],
        };
        let vex = Vex::build(
            &[VexEntry {
                dep: &d,
                decision: &dec,
            }],
            &"b".repeat(64),
            ts(),
        );
        let s = &vex.statements[0];
        assert_eq!(s.status, Status::UnderInvestigation);
        assert!(s.impact_statement.is_some());
        assert!(s.action_statement.is_none());
    }

    #[test]
    fn statements_sorted_and_id_stable() {
        let a = dep("a", "1");
        let b = dep("b", "1");
        let block = Decision::Block {
            reasons: vec![Reason::ExoticSource { kind: "git".into() }],
        };
        let warn = Decision::Warn {
            reasons: vec![Reason::PublishedAtUnknown],
        };
        let entries = vec![
            VexEntry {
                dep: &b,
                decision: &warn,
            },
            VexEntry {
                dep: &a,
                decision: &block,
            },
        ];
        let digest = "deadbeef".repeat(8);
        let v1 = Vex::build(&entries, &digest, ts());
        let v2 = Vex::build(&entries, &digest, ts());
        assert_eq!(v1, v2);
        // sorted: "exotic-source" before "published-at-unknown"
        assert_eq!(v1.statements[0].vulnerability.name, "exotic-source");
        assert_eq!(v1.statements[1].vulnerability.name, "published-at-unknown");
        assert!(v1.id.ends_with(&digest));
    }
}
