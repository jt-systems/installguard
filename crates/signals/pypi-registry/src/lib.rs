//! PyPI JSON API signal provider.
//!
//! Hits `GET https://pypi.org/pypi/<name>/<version>/json` for each
//! resolved PyPI dependency and emits two metadata signals:
//!
//! * [`Signal::PublishedAt`] — the upload time of the first
//!   distribution file for that exact release. PyPI's per-file
//!   `upload_time_iso_8601` is the canonical timestamp; we pick
//!   the earliest across all files (sdist + wheels) so the value
//!   is independent of which platform-specific wheel happens to
//!   come first in the response.
//! * [`Signal::DeprecatedVersion`] — when `info.yanked == true`.
//!   PyPI's "yanked" semantics
//!   ([PEP 592](https://peps.python.org/pep-0592/)) match
//!   InstallGuard's `DeprecatedVersion` model: an installable but
//!   discouraged version. The maintainer-supplied
//!   `info.yanked_reason` becomes the deprecation message.
//!
//! Then, if the release exposes at least one distribution file,
//! a second probe runs against PyPI's [Integrity API]
//! (`GET /integrity/<project>/<version>/<filename>/provenance`)
//! for the canonical sdist (preferred) or first wheel. A `200`
//! response means the file has [PEP 740] attestations from a
//! Trusted Publisher that PyPI cryptographically verified at
//! upload time. We surface that with [`Signal::ProvenanceClaimed`]
//! — the same shape npm provenance uses, since the trust
//! semantics align: a structurally-verified attestation linking
//! the published distribution to a known publisher identity.
//! Anything other than `200` (typically `404` — most projects
//! have not adopted Trusted Publishers yet) is silent: absence
//! is not suspicious.
//!
//! [Integrity API]: https://docs.pypi.org/api/integrity/
//! [PEP 740]: https://peps.python.org/pep-0740/
//!
//! ## Out of scope (deferred to follow-up slices)
//!
//! * Maintainer / publisher *change* signals — PyPI's JSON API
//!   does not expose per-version publisher identity in a stable
//!   form, and the Integrity API only carries the publisher when
//!   attestations are present. [`Signal::PublisherChange`] and
//!   [`Signal::MaintainerNewAccount`] cannot be derived
//!   reliably yet.
//! * `Signal::LifecycleScripts` / `Signal::SuspiciousScript` — Python
//!   sdists execute `setup.py` at install time, but inspecting the
//!   tarball requires a download + extract, which is a different
//!   shape from the metadata-only providers shipping today. Tracked
//!   separately as the "sdist scan" slice.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;

const DEFAULT_BASE: &str = "https://pypi.org/pypi";
const DEFAULT_INTEGRITY_BASE: &str = "https://pypi.org/integrity";
const USER_AGENT: &str = concat!(
    "installguard-signal-pypi-registry/",
    env!("CARGO_PKG_VERSION")
);

#[derive(Debug)]
pub struct PypiRegistryProvider {
    client: reqwest::Client,
    base: String,
    integrity_base: String,
}

impl PypiRegistryProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_bases(DEFAULT_BASE, DEFAULT_INTEGRITY_BASE)
    }

    pub fn with_base(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        Self::with_bases(base, DEFAULT_INTEGRITY_BASE)
    }

    pub fn with_bases(
        base: impl Into<String>,
        integrity_base: impl Into<String>,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base: base.into().trim_end_matches('/').to_string(),
            integrity_base: integrity_base.into().trim_end_matches('/').to_string(),
        })
    }
}

#[async_trait]
impl SignalProvider for PypiRegistryProvider {
    fn id(&self) -> &'static str {
        "pypi-registry"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        matches!(dep.ecosystem, Ecosystem::Pypi)
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        // PyPI is case-insensitive and treats `-` / `_` / `.` as
        // equivalent (PEP 503). The adapter normalises the name
        // before we ever see it, so the path component is safe to
        // use verbatim.
        let url = format!("{}/{}/{}/json", self.base, dep.name, dep.version);
        tracing::debug!(url, "fetching pypi metadata");

        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(vec![Signal::Unavailable {
                provider: "pypi-registry".into(),
                reason: format!("HTTP {}", resp.status()),
            }]);
        }

        let body: PypiResponse = resp
            .json()
            .await
            .map_err(|e| SignalError::Decode(e.to_string()))?;

        let mut out = compute_signals(&body);

        // PEP 740 / PyPI Integrity API probe. Pick the canonical
        // file for this release, ask the index whether it has
        // attestations, and fold the result into the signal list.
        // Network errors here are silent: the metadata signals
        // are the contract for this provider; provenance is a
        // best-effort augmentation.
        if let Some(filename) = pick_attestation_filename(&body.urls) {
            if let Ok(Some(provenance_url)) = self
                .fetch_provenance_url(&dep.name, &dep.version, filename)
                .await
            {
                out.push(Signal::ProvenanceClaimed {
                    bundle_url: provenance_url,
                });
            }
        }

        Ok(out)
    }
}

impl PypiRegistryProvider {
    /// Probe PyPI's Integrity API for this file. Returns `Ok(Some(url))`
    /// when the index has provenance for the file (HTTP 200 against the
    /// integrity endpoint), `Ok(None)` for a clean 404 (no
    /// attestations — the common case today), and `Err` only on
    /// network failure. Other status codes are treated as "no
    /// attestation" because attestation absence is not suspicious.
    async fn fetch_provenance_url(
        &self,
        name: &str,
        version: &str,
        filename: &str,
    ) -> Result<Option<String>, SignalError> {
        let url = format!(
            "{}/{}/{}/{}/provenance",
            self.integrity_base, name, version, filename
        );
        tracing::debug!(url, "probing pypi integrity api");
        let resp = self
            .client
            .get(&url)
            .header(
                reqwest::header::ACCEPT,
                "application/vnd.pypi.integrity.v1+json",
            )
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::OK {
            // We don't need to parse the body — a 200 means PyPI
            // verified at least one attestation at upload time.
            // The URL itself is what callers use to re-fetch and
            // do their own deeper verification.
            Ok(Some(url))
        } else {
            Ok(None)
        }
    }
}

/// Pick the file we should ask PyPI's Integrity API about.
///
/// Prefers the sdist (`.tar.gz` / `.zip`); falls back to the first
/// wheel. Attestations are per-file on PyPI, but in practice the
/// publisher signs every artifact in a release with the same
/// trusted-publisher identity, so probing one file is enough to
/// detect provenance for the release.
#[must_use]
pub fn pick_attestation_filename(files: &[PypiFile]) -> Option<&str> {
    files
        .iter()
        .find(|f| {
            let name = f.filename.as_str();
            // sdists are .tar.gz or .zip; everything else (.whl,
            // .egg) is per-platform. .tar.gz isn't a single
            // filesystem extension so we keep that arm explicit.
            name.ends_with(".tar.gz")
                || std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        })
        .or_else(|| files.first())
        .map(|f| f.filename.as_str())
        .filter(|s| !s.is_empty())
}

/// Pure helper: derives the signal set from a deserialised PyPI
/// JSON response. Split out so it is unit-testable without
/// network access.
#[must_use]
pub fn compute_signals(body: &PypiResponse) -> Vec<Signal> {
    let mut out = Vec::new();
    if let Some(at) = earliest_upload(&body.urls) {
        out.push(Signal::PublishedAt { at });
    } else {
        out.push(Signal::Unavailable {
            provider: "pypi-registry".into(),
            reason: "no distribution files for this release".into(),
        });
    }
    if body.info.yanked {
        out.push(Signal::DeprecatedVersion {
            message: body
                .info
                .yanked_reason
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        });
    }
    out
}

fn earliest_upload(files: &[PypiFile]) -> Option<DateTime<Utc>> {
    files.iter().filter_map(|f| f.upload_time_iso_8601).min()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiResponse {
    #[serde(default)]
    pub info: PypiInfo,
    #[serde(default)]
    pub urls: Vec<PypiFile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PypiInfo {
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub yanked_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiFile {
    #[serde(default)]
    pub upload_time_iso_8601: Option<DateTime<Utc>>,
    #[serde(default)]
    pub filename: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_at(ts: &str) -> PypiFile {
        PypiFile {
            upload_time_iso_8601: Some(ts.parse().unwrap()),
            filename: String::new(),
        }
    }

    fn named_file(filename: &str) -> PypiFile {
        PypiFile {
            upload_time_iso_8601: Some("2024-06-01T12:00:00Z".parse().unwrap()),
            filename: filename.to_string(),
        }
    }

    #[test]
    fn published_at_picks_earliest_upload_across_files() {
        let body = PypiResponse {
            info: PypiInfo::default(),
            urls: vec![
                file_at("2024-06-01T12:00:00Z"),
                file_at("2024-06-01T11:00:00Z"),
                file_at("2024-06-01T13:00:00Z"),
            ],
        };
        let sigs = compute_signals(&body);
        match sigs.first().expect("at least one signal") {
            Signal::PublishedAt { at } => {
                assert_eq!(at.to_rfc3339(), "2024-06-01T11:00:00+00:00");
            }
            other => panic!("unexpected first signal {other:?}"),
        }
    }

    #[test]
    fn unavailable_when_no_distribution_files() {
        let body = PypiResponse {
            info: PypiInfo::default(),
            urls: vec![],
        };
        let sigs = compute_signals(&body);
        assert!(matches!(sigs.first(), Some(Signal::Unavailable { .. })));
    }

    #[test]
    fn yanked_release_emits_deprecated_with_reason() {
        let body = PypiResponse {
            info: PypiInfo {
                yanked: true,
                yanked_reason: Some("CVE-2024-XXXX".into()),
            },
            urls: vec![file_at("2024-06-01T12:00:00Z")],
        };
        let sigs = compute_signals(&body);
        let dep = sigs
            .iter()
            .find(|s| matches!(s, Signal::DeprecatedVersion { .. }))
            .expect("DeprecatedVersion present");
        match dep {
            Signal::DeprecatedVersion { message } => {
                assert_eq!(message.as_deref(), Some("CVE-2024-XXXX"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn yanked_with_empty_reason_drops_to_none() {
        let body = PypiResponse {
            info: PypiInfo {
                yanked: true,
                yanked_reason: Some(String::new()),
            },
            urls: vec![file_at("2024-06-01T12:00:00Z")],
        };
        let sigs = compute_signals(&body);
        match sigs
            .iter()
            .find(|s| matches!(s, Signal::DeprecatedVersion { .. }))
            .expect("DeprecatedVersion present")
        {
            Signal::DeprecatedVersion { message } => assert_eq!(message.as_deref(), None),
            _ => unreachable!(),
        }
    }

    #[test]
    fn non_yanked_release_does_not_emit_deprecated() {
        let body = PypiResponse {
            info: PypiInfo::default(),
            urls: vec![file_at("2024-06-01T12:00:00Z")],
        };
        let sigs = compute_signals(&body);
        assert!(!sigs
            .iter()
            .any(|s| matches!(s, Signal::DeprecatedVersion { .. })));
    }

    #[test]
    fn supports_only_pypi_ecosystem() {
        let provider = PypiRegistryProvider::new().expect("client");
        let pypi = ResolvedDependency {
            name: "requests".into(),
            version: "2.31.0".into(),
            ecosystem: Ecosystem::Pypi,
            source: installguard_core::dependency::Source::Pypi {
                url: "https://files.pythonhosted.org/x.tar.gz".into(),
            },
            integrity: None,
            direct: true,
            requested_by: Vec::new(),
        };
        assert!(provider.supports(&pypi));

        let npm = ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            source: installguard_core::dependency::Source::Registry {
                url: "https://registry.npmjs.org".into(),
            },
            ..pypi
        };
        assert!(!provider.supports(&npm));
    }

    #[test]
    fn id_is_stable() {
        let p = PypiRegistryProvider::new().expect("client");
        assert_eq!(p.id(), "pypi-registry");
    }

    // ── PEP 740 attestation lookup ────────────────────────────────────

    #[test]
    fn attestation_filename_prefers_sdist() {
        let files = vec![
            named_file("requests-2.31.0-py3-none-any.whl"),
            named_file("requests-2.31.0.tar.gz"),
            named_file("requests-2.31.0-cp39-cp39-macosx.whl"),
        ];
        assert_eq!(
            pick_attestation_filename(&files),
            Some("requests-2.31.0.tar.gz")
        );
    }

    #[test]
    fn attestation_filename_picks_zip_sdist_when_no_targz() {
        let files = vec![
            named_file("old-pkg-1.0-py3-none-any.whl"),
            named_file("old-pkg-1.0.zip"),
        ];
        assert_eq!(pick_attestation_filename(&files), Some("old-pkg-1.0.zip"));
    }

    #[test]
    fn attestation_filename_falls_back_to_first_wheel() {
        let files = vec![
            named_file("wheelonly-1.0-py3-none-any.whl"),
            named_file("wheelonly-1.0-cp39-cp39-linux.whl"),
        ];
        assert_eq!(
            pick_attestation_filename(&files),
            Some("wheelonly-1.0-py3-none-any.whl")
        );
    }

    #[test]
    fn attestation_filename_returns_none_for_empty() {
        assert_eq!(pick_attestation_filename(&[]), None);
    }

    #[test]
    fn attestation_filename_skips_blank_filename() {
        let files = vec![named_file("")];
        assert_eq!(pick_attestation_filename(&files), None);
    }
}
