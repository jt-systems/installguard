//! deps.dev project-metadata signal provider.
//!
//! Calls the v3alpha JSON API at `https://api.deps.dev/v3alpha/`
//! and emits a single [`Signal::ProjectMetadata`] per dependency
//! capturing the catalogue's view of the version's licenses and
//! whether the upstream project is archived. The pure helper
//! [`compute_project_metadata`] is unit-tested separately so
//! integration tests don't need network access.
//!
//! ## Wire shape
//!
//! Two-step lookup:
//!
//! 1. `GET /v3alpha/systems/npm/packages/<name>/versions/<ver>`
//!    \u2192 `{ "licenses": ["MIT"], "relatedProjects": [{ "projectKey": { "id": "github.com/owner/repo" }, "relationType": "SOURCE_REPO" }] }`
//! 2. (optional) `GET /v3alpha/projects/<projectKey.id>` \u2192
//!    `{ "openIssuesCount": .., "starsCount": .., "scorecard": {..} }`
//!
//! deps.dev does not currently expose an `archived` flag in its
//! v3alpha response, so [`Signal::ProjectMetadata::archived`] is
//! always `None` from this provider \u2014 the field exists for forward
//! compatibility with catalogues that do (e.g. a future GHSA-direct
//! provider). The license list is the high-value field today.
//!
//! ## Caching and rate-limit policy
//!
//! deps.dev imposes no documented rate limit but is a shared good;
//! the in-process cache is intentionally simple (per-provider
//! `Mutex<HashMap>`) and never hits disk. Callers that need cross-
//! run caching wrap us with [`installguard_cache::CachedProvider`]
//! at the framework level.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;

const DEFAULT_BASE: &str = "https://api.deps.dev/v3alpha";
const USER_AGENT: &str = concat!("installguard-signal-depsdev/", env!("CARGO_PKG_VERSION"));
const SOURCE: &str = "deps.dev";

#[derive(Debug)]
pub struct DepsDevProvider {
    client: reqwest::Client,
    base: String,
    cache: Mutex<HashMap<String, Option<VersionRecord>>>,
}

impl DepsDevProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_base(DEFAULT_BASE)
    }

    pub fn with_base(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self {
            client,
            base: base.into().trim_end_matches('/').to_string(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Fetch the deps.dev v3alpha version record.
    ///
    /// * `Ok(Some(record))` — deps.dev returned a 2xx with a
    ///   parseable body for this `(system, name, version)`.
    /// * `Ok(None)` — deps.dev returned 404 / 410. The package
    ///   simply isn't indexed yet (very common for fresh
    ///   releases). Cached as a soft miss so we don't retry.
    /// * `Err(reason)` — network failure, 5xx, or decode error.
    ///   **Not** cached, so a transient outage doesn't poison
    ///   the rest of the run; the caller surfaces this as a
    ///   `Signal::Unavailable` rather than letting absence look
    ///   like a clean signal.
    async fn fetch_version(
        &self,
        system: &str,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionRecord>, String> {
        // Cache key includes the system so npm:foo@1 and pypi:foo@1
        // never alias.
        let key = format!("{system}/{name}@{version}");
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(&key) {
                return Ok(hit.clone());
            }
        }
        let url = format!(
            "{}/systems/{}/packages/{}/versions/{}",
            self.base,
            system,
            urlencoding(name),
            urlencoding(version)
        );
        tracing::debug!(url, "fetching deps.dev version");
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("deps.dev request failed: {e}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            if let Ok(mut cache) = self.cache.lock() {
                cache.insert(key, None);
            }
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("deps.dev HTTP {status}"));
        }
        let record: VersionRecord = resp
            .json()
            .await
            .map_err(|e| format!("deps.dev decode failed: {e}"))?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, Some(record.clone()));
        }
        Ok(Some(record))
    }
}

#[async_trait]
impl SignalProvider for DepsDevProvider {
    fn id(&self) -> &'static str {
        "deps.dev"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        depsdev_system(dep.ecosystem).is_some()
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let Some(system) = depsdev_system(dep.ecosystem) else {
            return Ok(Vec::new());
        };
        match self.fetch_version(system, &dep.name, &dep.version).await {
            Ok(Some(record)) => Ok(vec![compute_project_metadata(&record)]),
            Ok(None) => {
                // Catalogue silence (404) is not an error — the
                // package may simply not be indexed yet. Emit
                // nothing; absence-as-suspicious is not the model.
                Ok(Vec::new())
            }
            Err(reason) => {
                // Network / 5xx / decode failures get surfaced as
                // an Unavailable signal so policy can choose to
                // gate on it (`severity: signal-unavailable: block`)
                // rather than silently treating an outage as
                // "no risk recorded".
                Ok(vec![Signal::Unavailable {
                    provider: "deps.dev".to_string(),
                    reason,
                }])
            }
        }
    }
}

/// Pure helper: builds a [`Signal::ProjectMetadata`] from a
/// deserialised v3alpha version record. Always returns a signal
/// even when the licence list is empty \u2014 the policy layer is the
/// place that decides whether emptiness is actionable.
#[must_use]
pub fn compute_project_metadata(record: &VersionRecord) -> Signal {
    Signal::ProjectMetadata {
        licenses: record.licenses.clone(),
        archived: None,
        source: SOURCE.to_string(),
    }
}
/// Maps an internal [`Ecosystem`] to the deps.dev system path
/// component. Returns `None` for ecosystems deps.dev does not
/// index, so the caller can short-circuit.
#[must_use]
pub fn depsdev_system(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn => Some("npm"),
        Ecosystem::Pypi => Some("pypi"),
    }
}
#[derive(Debug, Clone, Deserialize)]
pub struct VersionRecord {
    #[serde(default)]
    pub licenses: Vec<String>,
}

/// Minimal percent-encoder for path components. deps.dev URL-
/// encodes scoped package names (`@scope/name` \u2192 `%40scope%2Fname`)
/// so we encode `@`, `/`, `:` and any non-URL-safe byte.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_carries_license_list() {
        let r = VersionRecord {
            licenses: vec!["MIT".into(), "Apache-2.0".into()],
        };
        match compute_project_metadata(&r) {
            Signal::ProjectMetadata {
                licenses,
                archived,
                source,
            } => {
                assert_eq!(licenses, vec!["MIT", "Apache-2.0"]);
                assert_eq!(archived, None);
                assert_eq!(source, "deps.dev");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn metadata_empty_licenses_still_emitted() {
        let r = VersionRecord { licenses: vec![] };
        match compute_project_metadata(&r) {
            Signal::ProjectMetadata { licenses, .. } => assert!(licenses.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn urlencoding_handles_scoped_names() {
        assert_eq!(urlencoding("@scope/name"), "%40scope%2Fname");
        assert_eq!(urlencoding("plain"), "plain");
        assert_eq!(urlencoding("1.2.3"), "1.2.3");
        assert_eq!(urlencoding("1.2.3-rc.1+build"), "1.2.3-rc.1%2Bbuild");
    }
}
