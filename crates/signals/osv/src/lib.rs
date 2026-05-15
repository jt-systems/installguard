//! OSV.dev advisory signal provider.
//!
//! Queries the public [OSV API](https://osv.dev/) and emits one
//! [`Signal::AdvisoryKnown`] per matching vulnerability. OSV is a
//! consume-only data source — we never produce advisories from
//! local analysis through this provider.
//!
//! ## Wire shape
//!
//! ```text
//! POST https://api.osv.dev/v1/query
//! { "package": { "name": "<name>", "ecosystem": "npm" },
//!   "version": "<semver>" }
//! ```
//!
//! Response shape (relevant fields only):
//!
//! ```text
//! { "vulns": [
//!     { "id": "GHSA-xxxx-xxxx-xxxx",
//!       "summary": "...",
//!       "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..." } ] }
//! ] }
//! ```
//!
//! ## Source attribution
//!
//! OSV aggregates many upstream sources (GHSA, RustSec, PyPA, etc).
//! The `id` carries the source-namespaced identifier (`GHSA-...`,
//! `RUSTSEC-...`, etc) and the [`Signal::AdvisoryKnown::source`]
//! is set to `"osv"` to attribute the *delivery channel* — not the
//! upstream database. This mirrors how OSV documents itself and
//! lets a future GHSA-direct provider emit `source = "ghsa"`
//! without colliding.
//!
//! ## Severity bucketing
//!
//! OSV's `severity[]` is a list of CVSS strings; CVSS v3 base
//! scores map to the standard NVD buckets (low/medium/high/
//! critical). When OSV provides no severity (common for older
//! advisories or non-CVSS sources), we emit `severity = "unknown"`
//! and let the policy decide \(see [`AdvisorySeverity::from_signal`]).

use std::time::Duration;

use async_trait::async_trait;
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::{Deserialize, Serialize};

const DEFAULT_ENDPOINT: &str = "https://api.osv.dev/v1/query";
const USER_AGENT: &str = concat!("installguard-signal-osv/", env!("CARGO_PKG_VERSION"));
const SOURCE: &str = "osv";

#[derive(Debug)]
pub struct OsvProvider {
    client: reqwest::Client,
    endpoint: String,
}

impl OsvProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_endpoint(DEFAULT_ENDPOINT)
    }

    pub fn with_endpoint(endpoint: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
        })
    }
}

#[async_trait]
impl SignalProvider for OsvProvider {
    fn id(&self) -> &'static str {
        "osv"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        // OSV speaks for many ecosystems; only the npm family is
        // wired here because that's what the rest of the codebase
        // resolves today. Adding PyPI / crates.io is one match arm
        // each in [`ecosystem_label`].
        matches!(
            dep.ecosystem,
            Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn
        )
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let Some(ecosystem) = ecosystem_label(dep.ecosystem) else {
            return Ok(Vec::new());
        };
        let body = QueryBody {
            package: QueryPackage {
                name: &dep.name,
                ecosystem,
            },
            version: &dep.version,
        };
        tracing::debug!(name = %dep.name, version = %dep.version, "querying osv");
        let resp = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            // OSV returns 200 even for "no results"; a non-2xx is
            // a real failure. Surface it as Unavailable so the
            // dependency record still notes the gap.
            return Ok(vec![Signal::Unavailable {
                provider: "osv".into(),
                reason: format!("osv returned http {}", resp.status()),
            }]);
        }
        let payload: QueryResponse = resp
            .json()
            .await
            .map_err(|e| SignalError::Decode(e.to_string()))?;
        Ok(payload
            .vulns
            .into_iter()
            .map(|v| Signal::AdvisoryKnown {
                id: v.id,
                severity: bucket_severity(&v.severity),
                summary: v.summary.unwrap_or_default(),
                source: SOURCE.to_string(),
            })
            .collect())
    }
}

/// Maps an internal [`Ecosystem`] to the string OSV uses on the
/// wire. Returns `None` for ecosystems OSV does not recognise so
/// the caller can short-circuit without round-tripping the API.
//
// `Option` is structural here \u2014 the day a non-OSV-supported
// ecosystem (e.g. a hypothetical private registry kind) lands on
// the `Ecosystem` enum it must drop into the `None` arm without
// edits to this function. Suppress `unnecessary_wraps` because
// today's enum is exhaustive on OSV-supported ecosystems.
#[allow(clippy::unnecessary_wraps)]
fn ecosystem_label(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn => Some("npm"),
        // PyPI ecosystem is a type placeholder until ROADMAP M8 —
        // the OSV provider deliberately skips it (returns `None`)
        // until the PyPI signal slice wires up the `"PyPI"` label.
        Ecosystem::Pypi => None,
    }
}

/// Picks the highest-severity bucket from the OSV `severity[]`
/// list. CVSS v3 base scores map per the standard NVD buckets:
/// 0.1\u20133.9 = low, 4.0\u20136.9 = medium, 7.0\u20138.9 = high, 9.0\u201310.0 =
/// critical. Returns `"unknown"` when no parseable CVSS score is
/// present so downstream code never has to handle a missing
/// severity field.
fn bucket_severity(entries: &[OsvSeverity]) -> String {
    let mut best: Option<&'static str> = None;
    for entry in entries {
        if !entry.severity_type.starts_with("CVSS") {
            continue;
        }
        let Some(score) = parse_cvss_base_score(&entry.score) else {
            continue;
        };
        let bucket = if score >= 9.0 {
            "critical"
        } else if score >= 7.0 {
            "high"
        } else if score >= 4.0 {
            "medium"
        } else if score > 0.0 {
            "low"
        } else {
            continue;
        };
        // Use ordinals so "critical" beats "high" even if it
        // appears earlier in the list.
        if rank(bucket) > best.map_or(0, rank) {
            best = Some(bucket);
        }
    }
    best.unwrap_or("unknown").to_string()
}

fn rank(b: &str) -> u8 {
    match b {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Pulls the base score out of either a bare numeric string
/// (`"7.5"`) or a full CVSS vector with an embedded score
/// (`"CVSS:3.1/AV:N/.../A:H"` \u2014 in which case OSV usually also
/// emits the score as a separate entry; we only attempt the bare
/// form here and fall back to vector parsing). Returns `None` for
/// anything we cannot confidently parse.
fn parse_cvss_base_score(s: &str) -> Option<f32> {
    if let Ok(v) = s.parse::<f32>() {
        return Some(v);
    }
    // OSV occasionally embeds the numeric score after a `/S:` or
    // similar marker; we deliberately do NOT try to compute the
    // score from the vector ourselves \u2014 that's a CVSS calculator,
    // out of scope for a signal provider. Fall back to None and
    // let the caller bucket as "unknown".
    None
}

#[derive(Serialize)]
struct QueryBody<'a> {
    package: QueryPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct QueryPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(t: &str, s: &str) -> OsvSeverity {
        OsvSeverity {
            severity_type: t.to_string(),
            score: s.to_string(),
        }
    }

    #[test]
    fn severity_buckets_critical_when_score_above_nine() {
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "9.8")]), "critical");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "9.0")]), "critical");
    }

    #[test]
    fn severity_buckets_high_medium_low() {
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "8.9")]), "high");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "7.0")]), "high");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "6.9")]), "medium");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "4.0")]), "medium");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "3.9")]), "low");
        assert_eq!(bucket_severity(&[sev("CVSS_V3", "0.1")]), "low");
    }

    #[test]
    fn severity_picks_highest_bucket_in_list() {
        let list = [sev("CVSS_V3", "5.0"), sev("CVSS_V3", "9.5")];
        assert_eq!(bucket_severity(&list), "critical");
        let reverse = [sev("CVSS_V3", "9.5"), sev("CVSS_V3", "5.0")];
        assert_eq!(bucket_severity(&reverse), "critical");
    }

    #[test]
    fn severity_unknown_when_no_cvss_entries() {
        assert_eq!(bucket_severity(&[]), "unknown");
        assert_eq!(bucket_severity(&[sev("OTHER", "9.9")]), "unknown");
    }

    #[test]
    fn severity_unknown_when_score_is_unparseable_vector() {
        assert_eq!(
            bucket_severity(&[sev("CVSS_V3", "CVSS:3.1/AV:N/AC:L")]),
            "unknown"
        );
    }

    #[test]
    fn ecosystem_label_covers_npm_family() {
        assert_eq!(ecosystem_label(Ecosystem::Npm), Some("npm"));
        assert_eq!(ecosystem_label(Ecosystem::Pnpm), Some("npm"));
        assert_eq!(ecosystem_label(Ecosystem::Yarn), Some("npm"));
    }
}
