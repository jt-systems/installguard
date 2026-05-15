//! PyPI JSON API signal provider.
//!
//! Hits `GET https://pypi.org/pypi/<name>/<version>/json` for each
//! resolved PyPI dependency and emits two signals:
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
//! ## Out of scope (deferred to follow-up slices)
//!
//! * Maintainer / publisher signals — PyPI's JSON API does not
//!   expose per-version publisher identity, so
//!   [`Signal::PublisherChange`] and
//!   [`Signal::MaintainerNewAccount`] cannot be derived from this
//!   endpoint alone.
//! * `Signal::LifecycleScripts` / `Signal::SuspiciousScript` — Python
//!   sdists execute `setup.py` at install time, but inspecting the
//!   tarball requires a download + extract, which is a different
//!   shape from the metadata-only providers shipping today. Tracked
//!   separately as the "sdist scan" slice.
//! * Scorecard wiring — the OpenSSF Scorecard provider needs a
//!   repo URL, which lives in `info.project_urls`. Plumbing that
//!   through requires changes to the Scorecard provider; deferred
//!   so this slice stays focused.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;

const DEFAULT_BASE: &str = "https://pypi.org/pypi";
const USER_AGENT: &str = concat!(
    "installguard-signal-pypi-registry/",
    env!("CARGO_PKG_VERSION")
);

#[derive(Debug)]
pub struct PypiRegistryProvider {
    client: reqwest::Client,
    base: String,
}

impl PypiRegistryProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_base(DEFAULT_BASE)
    }

    pub fn with_base(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base: base.into().trim_end_matches('/').to_string(),
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

        Ok(compute_signals(&body))
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_at_picks_earliest_upload_across_files() {
        let body = PypiResponse {
            info: PypiInfo::default(),
            urls: vec![
                PypiFile {
                    upload_time_iso_8601: Some("2024-06-01T12:00:00Z".parse().unwrap()),
                },
                PypiFile {
                    upload_time_iso_8601: Some("2024-06-01T11:00:00Z".parse().unwrap()),
                },
                PypiFile {
                    upload_time_iso_8601: Some("2024-06-01T13:00:00Z".parse().unwrap()),
                },
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
            urls: vec![PypiFile {
                upload_time_iso_8601: Some("2024-06-01T12:00:00Z".parse().unwrap()),
            }],
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
            urls: vec![PypiFile {
                upload_time_iso_8601: Some("2024-06-01T12:00:00Z".parse().unwrap()),
            }],
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
            urls: vec![PypiFile {
                upload_time_iso_8601: Some("2024-06-01T12:00:00Z".parse().unwrap()),
            }],
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
}
