//! OpenSSF Scorecard signal provider.
//!
//! Two-step lookup chained over HTTP:
//!
//! 1. Fetch the npm packument from `registry.npmjs.org` to read
//!    the `repository` field. We need this because Scorecard is
//!    keyed by source-repo URL, not package name.
//! 2. Normalise the repo URL into a `host/owner/repo` triple
//!    (currently github.com only — the dominant case; the
//!    securityscorecards.dev catalogue does index gitlab.com and
//!    bitbucket.org but coverage is sparse, deferred).
//! 3. `GET https://api.securityscorecards.dev/projects/<host>/<owner>/<repo>`
//!    \u2192 `{ "score": 7.3, "checks": [...] }`. Round to nearest
//!    integer (`u8`) for stable policy comparison and emit one
//!    [`Signal::ScorecardScore`].
//!
//! Any failure (no repo field, non-github host, 404 from
//! Scorecard) is silent — emits zero signals rather than an
//! Unavailable, because absence of a Scorecard entry is the
//! steady state for ~95% of npm packages and we don't want to
//! flood audit logs.
//!
//! Pure helpers ([`extract_repo_triple`], [`bucket_score`]) are
//! unit-tested separately.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;

const NPM_BASE: &str = "https://registry.npmjs.org";
const PYPI_BASE: &str = "https://pypi.org/pypi";
const SCORECARD_BASE: &str = "https://api.securityscorecards.dev";
const USER_AGENT: &str = concat!("installguard-signal-scorecard/", env!("CARGO_PKG_VERSION"));
const SOURCE: &str = "openssf-scorecard";

#[derive(Debug)]
pub struct ScorecardProvider {
    client: reqwest::Client,
    npm_base: String,
    pypi_base: String,
    scorecard_base: String,
    cache: Mutex<HashMap<String, Option<u8>>>,
}

impl ScorecardProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_bases(NPM_BASE, PYPI_BASE, SCORECARD_BASE)
    }

    pub fn with_bases(
        npm_base: impl Into<String>,
        pypi_base: impl Into<String>,
        scorecard_base: impl Into<String>,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Self {
            client,
            npm_base: npm_base.into().trim_end_matches('/').to_string(),
            pypi_base: pypi_base.into().trim_end_matches('/').to_string(),
            scorecard_base: scorecard_base.into().trim_end_matches('/').to_string(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    async fn fetch_npm_repo_url(&self, name: &str) -> Option<String> {
        let url = format!("{}/{}", self.npm_base, encode_npm_name(name));
        tracing::debug!(url, "fetching npm packument for repo discovery");
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let pkg: NpmPackument = resp.json().await.ok()?;
        pkg.repository.and_then(|r| match r {
            RepoField::Url(u) => Some(u),
            RepoField::Object { url } => url,
        })
    }

    async fn fetch_pypi_repo_url(&self, name: &str, version: &str) -> Option<String> {
        // PyPI is case- and separator-insensitive (PEP 503); the
        // adapter normalises the name before any provider sees it,
        // so the path is safe verbatim.
        let url = format!("{}/{}/{}/json", self.pypi_base, name, version);
        tracing::debug!(url, "fetching pypi metadata for repo discovery");
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: PypiResponse = resp.json().await.ok()?;
        pick_pypi_repo_url(&body.info)
    }

    /// Fetch the OpenSSF Scorecard for a `host/owner/repo` triple.
    ///
    /// * `Ok(Some(score))` — Scorecard returned a 2xx with a
    ///   parseable body.
    /// * `Ok(None)` — Scorecard returned 404. The project is
    ///   not indexed; cached as a soft miss.
    /// * `Err(reason)` — network failure, 5xx, or decode error.
    ///   Not cached. Caller surfaces as `Signal::Unavailable`
    ///   so a Scorecard outage doesn't masquerade as "no risk
    ///   recorded" on a clean run.
    async fn fetch_score(&self, repo: &str) -> Result<Option<u8>, String> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(repo) {
                return Ok(*hit);
            }
        }
        let url = format!("{}/projects/{}", self.scorecard_base, repo);
        tracing::debug!(url, "fetching scorecard");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("scorecard request failed: {e}"))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            if let Ok(mut cache) = self.cache.lock() {
                cache.insert(repo.to_string(), None);
            }
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("scorecard HTTP {status}"));
        }
        let body: ScorecardResponse = resp
            .json()
            .await
            .map_err(|e| format!("scorecard decode failed: {e}"))?;
        let score = bucket_score(body.score);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(repo.to_string(), Some(score));
        }
        Ok(Some(score))
    }
}

#[async_trait]
impl SignalProvider for ScorecardProvider {
    fn id(&self) -> &'static str {
        "openssf-scorecard"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        matches!(
            dep.ecosystem,
            Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn | Ecosystem::Pypi
        )
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let repo_url = match dep.ecosystem {
            Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn => {
                self.fetch_npm_repo_url(&dep.name).await
            }
            Ecosystem::Pypi => self.fetch_pypi_repo_url(&dep.name, &dep.version).await,
        };
        // Repo discovery is best-effort — silent on absence so we
        // don't double-count packument / metadata fetcher failures
        // already surfaced by the npm-registry / pypi-registry
        // providers. The load-bearing failure mode is the
        // Scorecard service itself, which we surface below.
        let Some(repo_url) = repo_url else {
            return Ok(Vec::new());
        };
        let Some(triple) = extract_repo_triple(&repo_url) else {
            return Ok(Vec::new());
        };
        match self.fetch_score(&triple).await {
            Ok(Some(score)) => Ok(vec![Signal::ScorecardScore {
                score,
                repo: triple,
                source: SOURCE.to_string(),
            }]),
            Ok(None) => Ok(Vec::new()),
            Err(reason) => Ok(vec![Signal::Unavailable {
                provider: "openssf-scorecard".to_string(),
                reason,
            }]),
        }
    }
}

/// Rounds Scorecard's `f32` aggregate score to the nearest `u8`
/// in `[0, 10]`. Out-of-range inputs (Scorecard occasionally
/// returns -1 for "no data") clamp to 0 so policy comparisons
/// degrade safely.
#[must_use]
pub fn bucket_score(raw: f32) -> u8 {
    if !raw.is_finite() || raw <= 0.0 {
        return 0;
    }
    let r = raw.round();
    if r >= 10.0 {
        return 10;
    }
    // Already non-negative and <10, so the cast is lossless.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let v = r as u8;
    v
}

/// Normalises a repository URL into a `host/owner/repo` triple,
/// returning `None` if the URL is missing, malformed, or refers
/// to a host Scorecard does not index. Recognised inputs:
///
/// - `git+https://github.com/foo/bar.git`
/// - `git://github.com/foo/bar`
/// - `https://github.com/foo/bar`
/// - `github:foo/bar` (npm shorthand)
/// - `git+ssh://git@github.com/foo/bar.git`
///
/// Currently github.com only — the dominant case for npm.
#[must_use]
pub fn extract_repo_triple(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // npm shorthand `github:foo/bar`
    if let Some(rest) = s.strip_prefix("github:") {
        return finalise("github.com", rest);
    }
    // Strip a leading `git+` scheme prefix.
    let s = s.strip_prefix("git+").unwrap_or(s);
    // Drop scheme.
    let no_scheme = s.split_once("://").map_or(s, |(_, rest)| rest);
    // Drop optional `user@` prefix (ssh form).
    let no_userinfo = no_scheme
        .split_once('@')
        .map_or(no_scheme, |(_, rest)| rest);
    // Split host / path.
    let (host, path) = no_userinfo.split_once('/')?;
    // Some forms use `git@github.com:foo/bar`; in that case the
    // host carries a trailing colon-path separator that we won't
    // see here because we already split on `@`. Defensive: also
    // accept `host:owner/repo` when no slash precedes the colon.
    let (host, path) = if let Some((h, p)) = host.split_once(':') {
        (h, format!("{p}/{path}"))
    } else {
        (host, path.to_string())
    };
    if !host.eq_ignore_ascii_case("github.com") {
        return None;
    }
    finalise("github.com", &path)
}

fn finalise(host: &str, path: &str) -> Option<String> {
    let cleaned = path.trim_end_matches('/').trim_end_matches(".git");
    let mut segs = cleaned.splitn(3, '/');
    let owner = segs.next()?.trim();
    let repo = segs.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{host}/{owner}/{repo}"))
}

fn encode_npm_name(s: &str) -> String {
    // npm packument URLs accept `@scope/name` URL-encoded as
    // `@scope%2fname` — the `@` itself is left literal.
    s.replace('/', "%2F")
}

#[derive(Debug, Deserialize)]
struct NpmPackument {
    #[serde(default)]
    repository: Option<RepoField>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RepoField {
    Url(String),
    Object {
        #[serde(default)]
        url: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct ScorecardResponse {
    #[serde(default)]
    score: f32,
}

#[derive(Debug, Default, Deserialize)]
pub struct PypiInfo {
    #[serde(default)]
    pub home_page: Option<String>,
    #[serde(default)]
    pub project_urls: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PypiResponse {
    #[serde(default)]
    info: PypiInfo,
}

/// Picks the most-likely upstream source-repo URL out of a PyPI
/// `info` block. Walks `project_urls` in a preference order
/// (`Source`, `Repository`, `Source Code`, `Code`, then anything
/// containing `github.com`) before falling back to `home_page`.
/// Returns the raw URL; downstream [`extract_repo_triple`] is
/// responsible for parsing it into a `host/owner/repo` triple
/// (and rejecting non-github hosts).
///
/// Match is case-insensitive on the key and tolerates the
/// inconsistent labelling PyPI maintainers use in the wild
/// (`Source code`, `source-code`, `repo`, `Repository`, etc).
#[must_use]
pub fn pick_pypi_repo_url(info: &PypiInfo) -> Option<String> {
    // Preference order over normalised keys.
    const PREFERRED: &[&str] = &["source", "repository", "source code", "sourcecode", "code"];
    let normalise = |k: &str| {
        k.trim()
            .to_ascii_lowercase()
            .replace(['-', '_'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let urls: Vec<(String, &String)> = info
        .project_urls
        .iter()
        .map(|(k, v)| (normalise(k), v))
        .collect();
    for needle in PREFERRED {
        if let Some((_, v)) = urls.iter().find(|(k, _)| k == needle) {
            return Some((*v).clone());
        }
    }
    // Last resort over project_urls: any value that mentions
    // github.com — many projects only set `Homepage` to their
    // GitHub Pages site, but list the repo under a custom key.
    if let Some((_, v)) = urls
        .iter()
        .find(|(_, v)| v.to_ascii_lowercase().contains("github.com"))
    {
        return Some((*v).clone());
    }
    info.home_page.clone().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_score_clamps_and_rounds() {
        assert_eq!(bucket_score(7.3), 7);
        assert_eq!(bucket_score(7.5), 8);
        assert_eq!(bucket_score(0.0), 0);
        assert_eq!(bucket_score(-1.0), 0);
        assert_eq!(bucket_score(10.0), 10);
        assert_eq!(bucket_score(11.0), 10);
        assert_eq!(bucket_score(f32::NAN), 0);
    }

    #[test]
    fn extract_repo_triple_handles_common_shapes() {
        let cases = [
            ("https://github.com/foo/bar", "github.com/foo/bar"),
            ("https://github.com/foo/bar.git", "github.com/foo/bar"),
            ("git+https://github.com/foo/bar.git", "github.com/foo/bar"),
            ("git://github.com/foo/bar", "github.com/foo/bar"),
            ("github:foo/bar", "github.com/foo/bar"),
            ("git+ssh://git@github.com/foo/bar.git", "github.com/foo/bar"),
            ("https://github.com/foo/bar/tree/main", "github.com/foo/bar"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                extract_repo_triple(input).as_deref(),
                Some(expected),
                "input={input}"
            );
        }
    }

    #[test]
    fn extract_repo_triple_rejects_non_github() {
        assert_eq!(extract_repo_triple("https://gitlab.com/foo/bar"), None);
        assert_eq!(extract_repo_triple(""), None);
        assert_eq!(extract_repo_triple("not a url"), None);
        assert_eq!(extract_repo_triple("https://github.com/onlyone"), None);
    }

    #[test]
    fn encode_npm_name_handles_scopes() {
        assert_eq!(encode_npm_name("@scope/name"), "@scope%2Fname");
        assert_eq!(encode_npm_name("plain"), "plain");
    }

    fn pypi_info_with(pairs: &[(&str, &str)], home: Option<&str>) -> PypiInfo {
        PypiInfo {
            home_page: home.map(str::to_string),
            project_urls: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn pypi_picks_source_over_homepage() {
        let info = pypi_info_with(
            &[
                ("Homepage", "https://requests.readthedocs.io"),
                ("Source", "https://github.com/psf/requests"),
            ],
            None,
        );
        assert_eq!(
            pick_pypi_repo_url(&info).as_deref(),
            Some("https://github.com/psf/requests")
        );
    }

    #[test]
    fn pypi_picks_repository_label_case_insensitive() {
        let info = pypi_info_with(
            &[("repository", "https://github.com/foo/bar")],
            Some("https://example.com"),
        );
        assert_eq!(
            pick_pypi_repo_url(&info).as_deref(),
            Some("https://github.com/foo/bar")
        );
    }

    #[test]
    fn pypi_normalises_source_code_label() {
        let info = pypi_info_with(&[("Source-Code", "https://github.com/foo/bar")], None);
        assert_eq!(
            pick_pypi_repo_url(&info).as_deref(),
            Some("https://github.com/foo/bar")
        );
    }

    #[test]
    fn pypi_falls_back_to_any_github_url() {
        let info = pypi_info_with(
            &[
                ("Documentation", "https://docs.example.com"),
                ("Tracker", "https://github.com/foo/bar/issues"),
            ],
            None,
        );
        assert_eq!(
            pick_pypi_repo_url(&info).as_deref(),
            Some("https://github.com/foo/bar/issues")
        );
    }

    #[test]
    fn pypi_falls_back_to_home_page_last() {
        let info = pypi_info_with(&[], Some("https://github.com/foo/bar"));
        assert_eq!(
            pick_pypi_repo_url(&info).as_deref(),
            Some("https://github.com/foo/bar")
        );
    }

    #[test]
    fn pypi_returns_none_when_no_signal() {
        let info = pypi_info_with(&[("Docs", "https://docs.example.com")], None);
        assert_eq!(pick_pypi_repo_url(&info), None);
    }

    #[test]
    fn pypi_empty_home_page_does_not_count() {
        let info = pypi_info_with(&[], Some(""));
        assert_eq!(pick_pypi_repo_url(&info), None);
    }
}
