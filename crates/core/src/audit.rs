//! Append-only JSONL audit log for InstallGuard evaluations.
//!
//! Each evaluation appends:
//!
//! 1. One `run` record summarising the evaluation (timestamp, adapter,
//!    lockfile path, lockfile/policy digests, totals).
//! 2. One `decision` record per `DepResult` (package, decision, reasons).
//!
//! Records share a `schema_version` and a per-run `run_id` (UUID-shaped,
//! derived from the lockfile digest + timestamp) so a downstream
//! consumer can correlate `decision` rows back to the parent `run`.
//!
//! Output is deterministic per record (sorted reason codes) and the
//! file is opened with `append`-mode; concurrent runs interleave at
//! line boundaries, never mid-record. JSONL — one JSON object per
//! line, no surrounding array — is chosen so log shippers (vector,
//! fluent-bit, promtail, etc.) can ingest the file with their default
//! parsers.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::decision::{Decision, Reason};
use crate::dependency::ResolvedDependency;

pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// One row of input to `append`.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    pub dep: &'a ResolvedDependency,
    pub decision: &'a Decision,
}

/// Top-level metadata describing the run. Written first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RunRecord<'a> {
    schema_version: u32,
    #[serde(rename = "type")]
    type_: &'static str,
    run_id: &'a str,
    timestamp: DateTime<Utc>,
    tool: ToolInfo<'a>,
    adapter: &'a str,
    lockfile: &'a str,
    lockfile_digest: &'a str,
    policy_digest: &'a str,
    summary: Summary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DecisionRecord<'a> {
    schema_version: u32,
    #[serde(rename = "type")]
    type_: &'static str,
    run_id: &'a str,
    timestamp: DateTime<Utc>,
    name: &'a str,
    version: &'a str,
    direct: bool,
    decision: &'static str,
    reasons: Vec<&'a Reason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ToolInfo<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct Summary {
    total: usize,
    allow: usize,
    warn: usize,
    block: usize,
}

/// All inputs needed to write a complete run to the audit log.
#[derive(Debug, Clone, Copy)]
pub struct AuditRun<'a> {
    pub timestamp: DateTime<Utc>,
    pub tool_name: &'a str,
    pub tool_version: &'a str,
    pub adapter: &'a str,
    pub lockfile: &'a str,
    pub lockfile_digest: &'a str,
    pub policy_digest: &'a str,
    pub entries: &'a [AuditEntry<'a>],
}

impl AuditRun<'_> {
    /// Stable per-run identifier derived from lockfile digest + timestamp.
    /// Two runs with identical inputs at distinct wall-clock times still
    /// receive distinct run IDs (timestamp differs); two runs at the
    /// identical instant on identical inputs are treated as the same run
    /// and may safely collide.
    #[must_use]
    pub fn run_id(&self) -> String {
        let mut payload = String::with_capacity(self.lockfile_digest.len() + 32);
        payload.push_str(self.lockfile_digest);
        payload.push('@');
        payload.push_str(
            &self
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_string(),
        );
        let h = sha2_hex(payload.as_bytes());
        // 8-4-4-4-12 layout for visual familiarity; not RFC 4122.
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    }
}

/// Append a run + per-decision rows to the JSONL log at `path`. Creates
/// the file if it doesn't exist; never truncates.
pub fn append(path: &Path, run: &AuditRun<'_>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut w = BufWriter::new(f);
    write_records(&mut w, run)?;
    w.flush()?;
    Ok(())
}

fn write_records<W: Write>(w: &mut W, run: &AuditRun<'_>) -> std::io::Result<()> {
    let summary = summarise(run.entries);
    let run_id = run.run_id();
    let run_rec = RunRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        type_: "run",
        run_id: &run_id,
        timestamp: run.timestamp,
        tool: ToolInfo {
            name: run.tool_name,
            version: run.tool_version,
        },
        adapter: run.adapter,
        lockfile: run.lockfile,
        lockfile_digest: run.lockfile_digest,
        policy_digest: run.policy_digest,
        summary,
    };
    serde_json::to_writer(&mut *w, &run_rec).map_err(io_err)?;
    w.write_all(b"\n")?;

    for entry in run.entries {
        let mut reasons: Vec<&Reason> = match entry.decision {
            Decision::Allow => Vec::new(),
            Decision::Warn { reasons } | Decision::Block { reasons } => reasons.iter().collect(),
        };
        reasons.sort_by_key(|r| r.code());
        let rec = DecisionRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            type_: "decision",
            run_id: &run_id,
            timestamp: run.timestamp,
            name: &entry.dep.name,
            version: &entry.dep.version,
            direct: entry.dep.direct,
            decision: decision_label(entry.decision),
            reasons,
        };
        serde_json::to_writer(&mut *w, &rec).map_err(io_err)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

fn decision_label(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Warn { .. } => "warn",
        Decision::Block { .. } => "block",
    }
}

fn summarise(entries: &[AuditEntry<'_>]) -> Summary {
    let mut s = Summary {
        total: entries.len(),
        allow: 0,
        warn: 0,
        block: 0,
    };
    for e in entries {
        match e.decision {
            Decision::Allow => s.allow += 1,
            Decision::Warn { .. } => s.warn += 1,
            Decision::Block { .. } => s.block += 1,
        }
    }
    s
}

fn sha2_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Ecosystem, Source};
    use chrono::TimeZone;

    fn dep(name: &str) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: "1.0.0".into(),
            integrity: None,
            source: Source::Registry { url: String::new() },
            direct: true,
            requested_by: Vec::new(),
        }
    }

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn appends_run_then_decisions() {
        let tmp = std::env::temp_dir().join(format!("ig-audit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let d1 = dep("a");
        let d2 = dep("b");
        let dec_allow = Decision::Allow;
        let dec_block = Decision::Block {
            reasons: vec![Reason::DisallowedLifecycleScript {
                script: "preinstall".into(),
            }],
        };
        let entries = [
            AuditEntry {
                dep: &d1,
                decision: &dec_allow,
            },
            AuditEntry {
                dep: &d2,
                decision: &dec_block,
            },
        ];
        let run = AuditRun {
            timestamp: ts(),
            tool_name: "installguard",
            tool_version: "0.0.0",
            adapter: "npm",
            lockfile: "package-lock.json",
            lockfile_digest: &"a".repeat(64),
            policy_digest: &"b".repeat(64),
            entries: &entries,
        };
        append(&tmp, &run).unwrap();
        // append a second time to confirm we never truncate
        append(&tmp, &run).unwrap();

        let contents = std::fs::read_to_string(&tmp).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 6); // 2 runs * (1 run + 2 decisions)
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["type"], "run");
        assert_eq!(first["summary"]["total"], 2);
        assert_eq!(first["summary"]["allow"], 1);
        assert_eq!(first["summary"]["block"], 1);
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["type"], "decision");
        assert_eq!(second["run_id"], first["run_id"]);
        std::fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn run_id_stable_for_same_inputs() {
        let entries: [AuditEntry<'_>; 0] = [];
        let run = AuditRun {
            timestamp: ts(),
            tool_name: "installguard",
            tool_version: "0.0.0",
            adapter: "npm",
            lockfile: "x",
            lockfile_digest: &"a".repeat(64),
            policy_digest: &"b".repeat(64),
            entries: &entries,
        };
        assert_eq!(run.run_id(), run.run_id());
    }
}
